import streamlit as st
import sqlite3
import pandas as pd
import bcrypt
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

def init_db():
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()

    # Librarians Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS Librarians (
                        librarian_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')

    # Members Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS Members (
                        member_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL)''')

    # Books Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS Books (
                        book_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        author TEXT NOT NULL,
                        year INTEGER NOT NULL,
                        genre TEXT,
                        read_status BOOLEAN DEFAULT 0)''')

    # Borrowed Books Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS BorrowedBooks (
                        borrow_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        member_id INTEGER,
                        book_id INTEGER,
                        borrow_date DATE DEFAULT CURRENT_DATE,
                        return_date DATE NULL,
                        fine INTEGER DEFAULT 0,
                        fine_paid BOOLEAN DEFAULT 0,
                        FOREIGN KEY (member_id) REFERENCES Members(member_id),
                        FOREIGN KEY (book_id) REFERENCES Books(book_id))''')

    conn.commit()
    conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def register_librarian(username, password):
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Librarians (username, password) VALUES (?, ?)", (username, hash_password(password)))
    conn.commit()
    conn.close()

def authenticate_librarian(username, password):
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM Librarians WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and verify_password(password, result[0]):
        return True
    return False

def register_member(name, email):
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Members (name, email) VALUES (?, ?)", (name, email))
    conn.commit()
    conn.close()

def add_book(title, author, genre, year, read_status):
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Books (title, author, genre, year, read_status) VALUES (?, ?, ?, ?, ?)", 
                   (title, author, genre, year, read_status))
    conn.commit()
    conn.close()

def fetch_books():
    conn = sqlite3.connect("library.db")
    df = pd.read_sql("SELECT * FROM Books", conn)
    conn.close()
    return df

def remove_book(book_id):
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Books WHERE book_id=?", (book_id,))
    conn.commit()
    conn.close()

def book_statistics():
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM Books")
    total_books = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM Books WHERE read_status=1")
    read_books = cursor.fetchone()[0]

    percentage_read = (read_books / total_books * 100) if total_books > 0 else 0

    conn.close()
    return total_books, read_books, percentage_read

def search_books(query):
    conn = sqlite3.connect("library.db")
    df = pd.read_sql(f"SELECT * FROM Books WHERE title LIKE '%{query}%' OR author LIKE '%{query}%' OR genre LIKE '%{query}%'", conn)
    conn.close()
    return df

# Initialize DB
init_db()

st.title("📚 Library Management System")

# Session State for Authentication
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = ""

# Login/Register UI
if not st.session_state.authenticated:
    menu = ["Librarian Login", "Librarian Register", "Register Member"]
    choice = st.sidebar.selectbox("Select", menu)

    if choice == "Librarian Login":
        st.subheader("🔑 Librarian Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            if authenticate_librarian(username, password):
                st.session_state.authenticated = True
                st.session_state.username = username
                st.success(f"Welcome, Librarian {username}!")
                st.rerun()
            else:
                st.error("Invalid Username or Password")

    elif choice == "Librarian Register":
        st.subheader("📝 Register Librarian")
        new_username = st.text_input("Create Username")
        new_password = st.text_input("Create Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        if st.button("Register"):
            if new_password == confirm_password:
                register_librarian(new_username, new_password)
                st.success("Librarian registration successful! Please log in.")
            else:
                st.error("Passwords do not match!")

    elif choice == "Register Member":
        st.subheader("📝 Register Member")
        name = st.text_input("Member Name")
        email = st.text_input("Member Email")
        
        if st.button("Register Member"):
            register_member(name, email)
            st.success(f"Member '{name}' registered successfully!")

else:
    st.sidebar.subheader(f"Librarian: {st.session_state.username}")
    dashboard_choice = st.sidebar.selectbox("Dashboard", ["Add Book", "View Books", "Remove Book", "Statistics", "Search Book", "Logout"])

    if dashboard_choice == "Add Book":
        st.subheader("📖 Add a Book")
        title = st.text_input("Title")
        author = st.text_input("Author")
        year = st.number_input("Publication Year", min_value=1000, max_value=9999, step=1)
        genre = st.text_input("Genre")
        read_status = st.checkbox("Mark as Read")

        if st.button("Add Book"):
            add_book(title, author, genre, year, read_status)
            st.success(f"Book '{title}' added successfully!")
            st.rerun()

    elif dashboard_choice == "View Books":
        st.subheader("📚 All Books in Library")
        books = fetch_books()
        st.dataframe(books)

    elif dashboard_choice == "Remove Book":
        st.subheader("❌ Remove a Book")
        book_id = st.number_input("Enter Book ID to Remove", min_value=1, step=1)

        if st.button("Remove Book"):
            remove_book(book_id)
            st.success("Book removed successfully!")
            st.rerun()

    elif dashboard_choice == "Statistics":
        st.subheader("📊 Library Statistics")
        total_books, read_books, percentage_read = book_statistics()

        st.write(f"📘 **Total Books:** {total_books}")
        st.write(f"✅ **Books Read:** {read_books} ({percentage_read:.2f}%)")

        fig, ax = plt.subplots()
        ax.bar(["Total Books", "Read Books"], [total_books, read_books], color=["blue", "green"])
        ax.set_ylabel("Number of Books")
        ax.set_title("Library Book Statistics")

        st.pyplot(fig)

    elif dashboard_choice == "Search Book":
        st.subheader("🔍 Search for a Book")
        query = st.text_input("Enter Title, Author, or Genre")
        
        if st.button("Search"):
            results = search_books(query)
            if not results.empty:
                st.dataframe(results)
            else:
                st.warning("No books found!")

    elif dashboard_choice == "Logout":
        st.session_state.authenticated = False
        st.rerun()
