import csv
import re
import hashlib
import requests
import bcrypt
import os
import pandas as pd
import logging
from datetime import datetime

CSV_FILE = 'regno.csv'
LOGIN_ATTEMPTS_LIMIT = 5
API_KEY = '48d48cd999d24736b7a03d9ea56aa785'
LOG_FILE = 'news_logs.txt'

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)

def is_valid_password(password):
    regex = r'^(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
    return re.match(regex, password)

def load_users():
    if not os.path.exists(CSV_FILE):
        return pd.DataFrame(columns=['email', 'password', 'security_question', 'security_answer'])
    return pd.read_csv(CSV_FILE)

def save_user(email, password, security_question, security_answer):
    users = load_users()
    hashed_password = hash_password(password)
    hashed_answer = hash_password(security_answer)  
    
    new_user = pd.DataFrame({
        'email': [email], 
        'password': [hashed_password], 
        'security_question': [security_question],
        'security_answer': [hashed_answer]  
    })
    
    users = pd.concat([users, new_user], ignore_index=True)
    
    users.to_csv(CSV_FILE, index=False)

def register():
    users = load_users()
    while True:
        email = input("Enter your email: ")
        if not is_valid_email(email):
            print("Invalid email format. Please try again.")
            continue

        if not users[users['email'] == email].empty:
            print("Email already exists. Try logging in or use a different email.")
            return

        password = input("Enter a password (must be 8 characters long and contain at least one special character): ")
        if not is_valid_password(password):
            print("Password does not meet the requirements.")
            continue

        security_question = input("Enter a security question for password recovery: ")
        security_answer = input("Enter the answer to your security question: ")
        
        save_user(email, password, security_question, security_answer)
        print("Registration successful! You can now log in.")
        break

def login():
    users = load_users()
    attempts = 0
    while attempts < LOGIN_ATTEMPTS_LIMIT:
        email = input("Enter your email: ")
        password = input("Enter your password: ")

        if not is_valid_email(email):
            print("Invalid email format.")
            continue

        user = users[users['email'] == email]
        if user.empty:
            print("No user found with this email.")
            continue

        stored_password = user['password'].values[0]
        if check_password(stored_password, password):
            print("Login successful!")
            return email

        attempts += 1
        print(f"Invalid credentials. {LOGIN_ATTEMPTS_LIMIT - attempts} attempts left.")

    print("Too many failed login attempts. Try again later.")
    return None

def reset_password():
    users = load_users()
    email = input("Enter your registered email: ")
    user = users[users['email'] == email]

    if user.empty:
        print("No user found with this email.")
        return

    security_question = user['security_question'].values[0]
    answer = input(f"Answer the security question: {security_question}\n")

    stored_answer = user['security_answer'].values[0]
    if check_password(stored_answer, answer):
        new_password = input("Enter a new password (must be 8 characters long and contain at least one special character): ")
        if is_valid_password(new_password):
            users.loc[users['email'] == email, 'password'] = hash_password(new_password)
            users.to_csv(CSV_FILE, index=False)
            print("Password reset successfully!")
        else:
            print("Invalid password format.")
    else:
        print("Security question answer is incorrect.")

def fetch_news(email, keyword):
    url = f"https://newsapi.org/v2/everything?q={keyword}&apiKey={API_KEY}&pageSize=5"
    try:
        response = requests.get(url)
        response.raise_for_status()
        news_data = response.json()

        if news_data['totalResults'] == 0:
            print(f"No news found for the keyword: {keyword}")
            return

        print("\nTop 5 news headlines:")
        for article in news_data['articles']:
            headline = article['title']
            source = article['source']['name']
            print(f"Title: {headline}\nSource: {source}\n")
            
            logging.info(f'User: {email}, Keyword: "{keyword}", Headline: "{headline}", Source: "{source}"')

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"Error occurred: {err}")

def main():
    print("Welcome to the News Fetcher!")
    while True:
        choice = input("\n1. Login\n2. Register\n3. Forgot Password\n4. Exit\nChoose an option: ")

        if choice == '1':
            email = login()
            if email:
                keyword = input("Enter a keyword to search for news: ")
                fetch_news(email, keyword)
        elif choice == '2':
            register()
        elif choice == '3':
            reset_password()
        elif choice == '4':
            print("Exiting the application. Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
