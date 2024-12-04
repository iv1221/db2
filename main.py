import os
import pandas as pd
from tkinter import *
from tkinter import ttk, messagebox
from bson import ObjectId
import bson
from pymongo import MongoClient, ASCENDING
from datetime import datetime, timedelta, timezone
import psutil
import time
from functools import wraps
from pymongo import ReturnDocument

# Establish a client connection to the local MongoDB server
client = MongoClient('mongodb+srv://admin:admin1@test.td9jn.mongodb.net/?retryWrites=true&w=majority&appName=test')

# Define the database name
db_name = 'VCTMaster2024db'
db = client[db_name]
# Define the users collection for storing user credentials
users_collection = db['users']
change_log = db['change_log']
# List of collections to create
collections = [
    "users",
    "admin_list",
    "VEvents",
    "VPlayers",
    "VStats",
    "VTeams",
    "change_log"
]
# Ensure admin_list collection exists
admin_list_collection = db["admin_list"]

# Check if the admin_list collection is empty
if admin_list_collection.count_documents({}) == 0:
    # Create and insert default admin users
    default_admins = [
        {"username": "admin1", "password": "admin"},
        {"username": "admin2", "password": "admin"},
        {"username": "admin3", "password": "admin"},
    ]

    # Insert the default admins into the collection
    admin_list_collection.insert_many(default_admins)
    print("Default admins have been inserted into the admin_list collection.")
else:
    print("admin_list collection already contains data.")

# Print the admins in the collection for verification
for admin in admin_list_collection.find():
    print(admin)

# Create collections and insert default data (optional)
for collection_name in collections:
    if collection_name not in db.list_collection_names():
        db.create_collection(collection_name)
        print(f"Created collection: {collection_name}")
    else:
        print(f"Collection {collection_name} already exists")
# List of default collection names
default_collections = ["VEvents", "VPlayers", "VStats", "VTeams"]


# Function to load data from a CSV file, with a fallback to non-backup files
def load_data_from_csv(collection_name):
    backup_csv_filename = f"{collection_name}_backup.csv"
    fallback_filename = f"{collection_name}.csv"

    if os.path.exists(backup_csv_filename):
        # If the backup CSV file exists, load it into a DataFrame
        df = pd.read_csv(backup_csv_filename)
        print(f"Loaded data from {backup_csv_filename}")
        return df
    elif os.path.exists(fallback_filename):
        # If the fallback file exists, load it into a DataFrame
        df = pd.read_csv(fallback_filename)
        print(f"Loaded data from {fallback_filename}")
        return df
    else:
        print(f"Neither backup nor fallback file exists for {collection_name}.")
        return None
# Function to insert data into MongoDB
def insert_data_into_mongo(collection_name, data):
    collection = db[collection_name]
    # If data is a DataFrame, convert it to a list of dictionaries and insert
    if isinstance(data, pd.DataFrame):
        data_dict = data.to_dict(orient='records')  # Convert DataFrame to list of dicts
        if data_dict:
            collection.insert_many(data_dict)
            print(f"Inserted data into collection {collection_name}")
        else:
            print(f"No data to insert for {collection_name}")
    else:
        print(f"No valid data to insert for {collection_name}")
# Function to insert default data from CSV if collections are empty
def insert_default_data_from_csv():
    for collection_name in default_collections:
        collection = db[collection_name]

        # Check if collection is empty
        if collection.count_documents({}) == 0:
            # Load data from CSV if the collection is empty
            data = load_data_from_csv(collection_name)

            if data is not None:
                insert_data_into_mongo(collection_name, data)  # Insert data from CSV
            else:
                print(f"No data available for {collection_name}, skipping insertion.")
        else:
            print(f"Collection {collection_name} already contains data.")
# Function to export collection data to CSV files after insertion
def export_to_csv():
    for collection_name in collections:
        collection = db[collection_name]

        # Fetch all documents from the collection
        documents = collection.find()

        # Convert the documents to a DataFrame for easier export
        df = pd.DataFrame(list(documents))

        if not df.empty:
            # Remove the MongoDB '_id' field for the export
            if '_id' in df.columns:
                df.drop(columns=['_id'], inplace=True)

            # Save the DataFrame as a CSV file
            csv_filename = f"{collection_name}_backup.csv"
            df.to_csv(csv_filename, index=False)
            print(f"Backup saved to {csv_filename}")
        else:
            print(f"Collection {collection_name} is empty, no backup created.")


db['VPlayers'].create_index("playername")


sort_directions = {}
active_window = None

admin_list_collection = db["admin_list"]
if admin_list_collection.count_documents({}) == 0:
    # Create and insert default admin users
    default_admins = [
        {"username": "admin1", "password": "admin"},
        {"username": "admin2", "password": "admin"},
        {"username": "admin3", "password": "admin"},
    ]

for admin in admin_list_collection.find():
    print(admin)

def open_single_window(new_window_function):
    global active_window

    # Destroy the existing window if it exists
    if active_window is not None and active_window.winfo_exists():
        active_window.destroy()

    # Create the new window
    active_window = new_window_function()
class DatabaseLock:
    def __init__(self):
        self.active_admin = db["active_admin"]  # Collection for active admin
        self.active_users = db["active_users"]  # Collection for active users

        # Set auto-expiration for both collections (5 minutes of inactivity)
        self.active_admin.create_index([("timestamp", ASCENDING)], expireAfterSeconds=300)
        self.active_users.create_index([("timestamp", ASCENDING)], expireAfterSeconds=300)

    def can_open_window_for_admin(self, admin_id):
        # Check if any lock exists (by any admin)
        existing_lock = self.active_admin.find_one()

        if existing_lock:
            # An admin is already logged in
            if existing_lock["admin_id"] == admin_id:
                # Same admin trying to log in again
                return False, f"Admin {admin_id} is already logged in. Please log out first."
            else:
                # Another admin is logged in
                lock_time = existing_lock["timestamp"]
                return False, f"Admin access is locked by {existing_lock['admin_id']} since {lock_time}. Please wait or contact them."

        # No lock exists; create one atomically
        result = self.active_admin.find_one_and_update(
            {"admin_id": {"$exists": False}},  # Ensure no existing admin lock
            {"$set": {"admin_id": admin_id, "timestamp": datetime.now(timezone.utc)}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

        if result:
            return True, "Admin access granted"
        else:
            return False, "Failed to acquire lock. Please try again."

    def release_admin_lock(self, admin_id):
        result = self.active_admin.delete_one({"admin_id": admin_id})
        if result.deleted_count > 0:
            return True, f"Admin lock released for {admin_id}."
        return False, f"Failed to release lock. Admin {admin_id} does not own the lock."

    def track_user_activity(self, user_id):
        self.active_users.update_one(
            {"user_id": user_id},
            {"$set": {"user_id": user_id, "timestamp": datetime.now(timezone.utc)}},
            upsert=True,
        )

    def release_user_activity(self, user_id):
        self.active_users.delete_one({"user_id": user_id})


# Initialize the lock
db_lock = DatabaseLock()
def monitor_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        process = psutil.Process()  # Get the current process

        # Measure initial memory usage
        mem_before = process.memory_info().rss / (1024 ** 2)  # Convert to MB

        # Measure runtime
        start_time = time.time()
        result = func(*args, **kwargs)  # Execute the function
        end_time = time.time()

        # Measure final memory usage
        mem_after = process.memory_info().rss / (1024 ** 2)  # Convert to MB

        mem_used = mem_before - mem_after
        print(f"Memory Usage: {abs(mem_used):.6f} MB")

        # Print runtime
        runtime = end_time - start_time
        print(f"Runtime: {runtime:.6f} seconds")

        return result

    return wrapper
# Update logout or exit to release the lock
def logout_or_exit(user_id):
    db_lock.release_admin_lock(user_id)
    messagebox.showinfo("Logout", "You have logged out successfully.")
# Function to create a user account
def create_account():
    account_screen = Tk()
    account_screen.title("Create Account")

    Label(account_screen, text="Enter New Username:").grid(row=0, column=0, padx=10, pady=5)
    new_username_entry = Entry(account_screen)
    new_username_entry.grid(row=0, column=1, padx=10, pady=5)

    Label(account_screen, text="Enter New Password:").grid(row=1, column=0, padx=10, pady=5)
    new_password_entry = Entry(account_screen, show="*")
    new_password_entry.grid(row=1, column=1, padx=10, pady=5)

    def save_account():
        new_username = new_username_entry.get()
        new_password = new_password_entry.get()

        if new_username and new_password:
            # Check if username already exists
            if users_collection.find_one({"username": new_username}):
                messagebox.showerror("Error", "Username already exists. Please choose another one.")
            else:
                # Insert new user into the users collection
                users_collection.insert_one({"username": new_username, "password": new_password})
                messagebox.showinfo("Success", "User created successfully.")
                account_screen.destroy()
        else:
            messagebox.showerror("Error", "Please fill in both fields.")

    Button(account_screen, text="Create Account", command=save_account).grid(row=2, column=1, pady=10)
    account_screen.mainloop()
# Function to create the login screen
def create_login_screen():
    global login_screen, username_entry, password_entry
    login_screen = Tk()
    login_screen.title("Login")

    Label(login_screen, text="Username:").grid(row=0, column=0, padx=10, pady=5)
    username_entry = Entry(login_screen)
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    Label(login_screen, text="Password:").grid(row=1, column=0, padx=10, pady=5)
    password_entry = Entry(login_screen, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()

        # Check if the user is an admin
        admin_user = admin_list_collection.find_one({"username": username, "password": password})

        if admin_user:
            # Enforce lock for admin login
            can_access, message = db_lock.can_open_window_for_admin(username)
            if not can_access:
                messagebox.showerror("Access Denied", message)
                return

            # Admin login successful
            messagebox.showinfo("Login Successful", "Admin logged in successfully.")
            db_lock.track_user_activity(username)  # Track admin activity
            login_screen.destroy()
            create_gui(username)  # Open the main GUI with all features for the admin
        else:
            # Regular user login (no lock needed)
            user = users_collection.find_one({"username": username, "password": password})
            if user:
                messagebox.showinfo("Login Successful", "User logged in successfully.")
                db_lock.track_user_activity(username)  # Track user activity
                login_screen.destroy()
                create_search_gui()  # Open the Search GUI for regular users
            else:
                messagebox.showerror("Login Unsuccessful", "Incorrect username or password. Please try again.")

    # Buttons for login and account creation
    login_button = Button(login_screen, text="Login", command=attempt_login)
    login_button.grid(row=2, column=1, pady=10)

    create_account_button = Button(login_screen, text="Create Account", command=create_account)
    create_account_button.grid(row=3, column=1, pady=5)

    login_screen.mainloop()
# Function to create the Search tab for regular users
def create_search_gui():
    root = Tk()
    root.title(f"{db_name} Search Page")

    # Create a Notebook widget for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')

    # Add the Search tab
    create_search_tab(notebook)

    root.mainloop()

# Function to create the Search tab
def create_search_tab(notebook):
    # Create a new frame for the Search tab
    search_frame = ttk.Frame(notebook)
    notebook.add(search_frame, text="Search")

    # Labels and Entry fields for search inputs
    Label(search_frame, text="Player Name:").grid(row=0, column=0, padx=10, pady=5)
    player_entry = Entry(search_frame)
    player_entry.grid(row=0, column=1, padx=10, pady=5)

    Label(search_frame, text="Team Name:").grid(row=1, column=0, padx=10, pady=5)
    team_entry = Entry(search_frame)
    team_entry.grid(row=1, column=1, padx=10, pady=5)

    Label(search_frame, text="Event Name:").grid(row=2, column=0, padx=10, pady=5)
    event_entry = Entry(search_frame)
    event_entry.grid(row=2, column=1, padx=10, pady=5)

    # Frame to hold the Treeview and scrollbar
    result_frame = Frame(search_frame)
    result_frame.grid(row=4, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

    # Scrollbar for the Treeview
    scrollbar = Scrollbar(result_frame, orient="vertical")
    scrollbar.pack(side="right", fill="y")

    # Treeview to display search results
    result_tree = ttk.Treeview(result_frame, show='headings', yscrollcommand=scrollbar.set)
    result_tree.pack(expand=True, fill='both')
    scrollbar.config(command=result_tree.yview)

    # Adjust Treeview Columns
    result_tree["columns"] = ("_id", "Name", "Team", "Event", "KDR")

    # Define columns in the Treeview
    result_tree.heading("_id", text="ID", anchor="center")
    result_tree.heading("Name", text="Name", anchor="center")
    result_tree.heading("Team", text="Team", anchor="center")
    result_tree.heading("Event", text="Event", anchor="center")
    result_tree.heading("KDR", text="KDR", anchor="center")

    # Set column widths
    result_tree.column("_id", anchor="center", width=120)
    result_tree.column("Name", anchor="center", width=200)
    result_tree.column("Team", anchor="center", width=150)
    result_tree.column("Event", anchor="center", width=400)
    result_tree.column("KDR", anchor="center", width=100)

    @monitor_performance
    def perform_search():
        # Clear previous results
        for row in result_tree.get_children():
            result_tree.delete(row)

        # Get search terms from entries
        player_name = player_entry.get().strip()
        team_name = team_entry.get().strip()
        event_name = event_entry.get().strip()

        # Refine queries
        stats_query = {}

        # Event Name Search
        event_results = []
        if event_name:
            event_results = list(db['VEvents'].find({"event_name": {"$regex": event_name, "$options": "i"}}))
            event_names = [event.get("event_name") for event in event_results]
            if event_names:
                stats_query["event_name"] = {"$in": event_names}

        # Team Name Search
        matching_player_names = []
        if team_name:
            matching_players = db['VPlayers'].find(
                {"teamname": {"$regex": team_name, "$options": "i"}},
                {"playername": 1}
            )
            matching_player_names = [player["playername"] for player in matching_players]

        # Player Name Search
        if player_name:
            if matching_player_names:
                # Combine player name and team name
                stats_query["playernames"] = {
                    "$regex": player_name,
                    "$options": "i",
                    "$in": matching_player_names
                }
            else:
                # Only filter by player name
                stats_query["playernames"] = {"$regex": player_name, "$options": "i"}
        elif matching_player_names:
            # Only filter by team name if no player name provided
            stats_query["playernames"] = {"$in": matching_player_names}

        # Query collection_stats with the refined query
        stats_results = db['VStats'].find(stats_query)

        # Populate results in TreeView
        results_found = False
        for stat in stats_results:
            results_found = True
            # Get the player's team name from collection_players
            player_data = db['VPlayers'].find_one({"playername": stat.get("playernames")})
            team_name = player_data.get("teamname") if player_data else "Unknown"

            result_tree.insert("", "end", values=(
                stat.get("_id"),
                stat.get("playernames"),
                team_name,
                stat.get("event_name"),
                stat.get("kdr")
            ))

        # Handle case where no stats are found
        if not results_found:
            result_tree.insert("", "end", values=("-", "No results found", "-", "-", "-"))

    # Search Button
    Button(search_frame, text="Search", command=perform_search).grid(row=3, column=1, pady=10)

# Function to refresh data in Treeview
def refresh_treeview(collection_name, tree, columns, sort_column=None, ascending=True):
    # Fetch sorted documents if sorting is requested
    if sort_column:
        sort_order = 1 if ascending else -1
        documents = list(db[collection_name].find().sort(sort_column, sort_order))
    else:
        documents = list(db[collection_name].find())

    # Clear existing rows
    for row in tree.get_children():
        tree.delete(row)

    # Insert new rows
    for document in documents:
        values = [document.get(column, "") for column in columns]
        tree.insert("", "end", values=values, iid=str(document["_id"]))  # Store `_id` as the row identifier

def sort_column_click(event, collection_name, tree, column):
    # Toggle sort direction
    sort_directions[column] = not sort_directions.get(column, True)
    refresh_treeview(collection_name, tree, tree["columns"], column, sort_directions[column])

# Helper function to convert the entry ID if needed
def convert_id(entry_id):
    # Attempt to convert the entry ID to an ObjectId if it’s a valid 24-character hex string
    try:
        return ObjectId(entry_id)
    except bson.errors.InvalidId:
        # If the ID is not a valid ObjectId, return it as-is (for integer or string IDs)
        return entry_id
    # Update Entry function

def log_admin_action(user, action, collection_name, details):
    change_log.insert_one({
        "admin": user,
        "action": action,
        "collection": collection_name,
        "details": details,
        "timestamp": datetime.now(timezone.utc)
    })

def add_entry(collection_name, tree, columns, user):
    def create_add_window():
        add_window = Toplevel()
        add_window.title(f"Add Entry to {collection_name}")
        entry_fields = []

        for i, column in enumerate(columns):
            Label(add_window, text=column).grid(row=i, column=0, padx=10, pady=5)
            entry_field = Entry(add_window)
            entry_field.grid(row=i, column=1, padx=10, pady=5)
            entry_fields.append(entry_field)

        Button(add_window, text="Submit", command=lambda: submit(entry_fields, add_window)).grid(row=len(columns), column=1, pady=10)

        return add_window

    @monitor_performance
    def submit(entry_fields, add_window):
        # Collect entry data from the input fields
        entry_data = {columns[i]: entry_fields[i].get() for i in range(len(columns))}

        # Validate that an "_id" field is provided
        if "_id" not in entry_data or not entry_data["_id"].strip():
            messagebox.showerror("Error", "The '_id' field is required and cannot be empty.")
            return

        # Validate the format of the "_id" field (if applicable)
        try:
            from bson import ObjectId
            entry_data["_id"] = ObjectId(entry_data["_id"]) if ObjectId.is_valid(entry_data["_id"]) else entry_data[
                "_id"]
        except Exception as e:
            messagebox.showerror("Error", f"Invalid '_id' format: {e}")
            return

        with client.start_session() as session:
            try:
                session.start_transaction()

                # Check if an entry with the same `_id` already exists
                if db[collection_name].find_one({"_id": entry_data["_id"]}, session=session):
                    raise Exception("An entry with this ID already exists.")

                # Insert the entry into the collection
                db[collection_name].insert_one(entry_data, session=session)

                # Log the admin action
                log_admin_action(user, "add", collection_name, {"new_entry": entry_data})

                # Notify the user of success
                messagebox.showinfo("Success", "Entry added successfully!")
                refresh_treeview(collection_name, tree, columns)
                add_window.destroy()
                session.commit_transaction()
            except Exception as e:
                session.abort_transaction()
                messagebox.showerror("Error", f"Failed to add entry. Rolled back to original state.\n{str(e)}")

    open_single_window(create_add_window)

def update_entry(collection_name, tree, columns, user):
    def create_update_window():
        update_window = Toplevel()
        update_window.title(f"Update Entry in {collection_name}")
        entry_fields = []

        for i, column in enumerate(columns):
            Label(update_window, text=column).grid(row=i, column=0, padx=10, pady=5)
            entry_field = Entry(update_window)
            if column == "_id":
                entry_field.insert(0, str(item_id))
                entry_field.config(state="disabled")
            else:
                entry_field.insert(0, tree.item(selected_item, 'values')[i])
            entry_field.grid(row=i, column=1, padx=10, pady=5)
            entry_fields.append(entry_field)

        Button(update_window, text="Submit", command=lambda: submit(entry_fields, update_window)).grid(row=len(columns), column=1, pady=10)

        return update_window

    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Warning", "Please select an item to update.")
        return

    item_id = tree.item(selected_item, "values")[0]  # Assuming `_id` is the first column

    @monitor_performance
    def submit(entry_fields, update_window):
        new_data = {}
        for i, column in enumerate(columns):
            if column == "_id":
                continue
            new_data[column] = entry_fields[i].get()

        converted_id = convert_id(item_id)
        with client.start_session() as session:
            try:
                session.start_transaction()
                collection = db[collection_name]
                original_data = collection.find_one({"_id": converted_id}, session=session)
                if not original_data:
                    raise Exception("Original document not found.")

                collection.update_one({"_id": converted_id}, {"$set": new_data}, session=session)
                log_admin_action(user, "update", collection_name, {
                    "original_data": original_data,
                    "updated_data": new_data
                })
                messagebox.showinfo("Success", "Entry updated successfully!")
                refresh_treeview(collection_name, tree, columns)
                update_window.destroy()
                session.commit_transaction()
            except Exception as e:
                session.abort_transaction()
                messagebox.showerror("Error", f"Failed to update entry. Rolled back to original state.\n{str(e)}")

    open_single_window(create_update_window)

@monitor_performance
def delete_entry(collection_name, tree, user):
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Warning", "Please select an item to delete.")
        return

    # Fetch the _id of the selected item
    item_id = tree.item(selected_item, "values")[0]  # Assuming `_id` is the first column

    # Convert item_id if necessary
    converted_id = convert_id(item_id)

    # Start a MongoDB session
    with client.start_session() as session:
        try:
            session.start_transaction()  # Start transaction

            # Prevent admins from deleting their own lock in `active_admin`
            if collection_name == "active_admin":
                record = db[collection_name].find_one({"_id": converted_id}, session=session)
                if record and record.get("admin_id") == user:
                    raise Exception("You cannot delete your own active lock.")

            # Fetch the document to create a save point
            collection = db[collection_name]
            original_document = collection.find_one({"_id": converted_id}, session=session)
            if not original_document:
                raise Exception("Document not found.")

            # Perform the delete operation
            collection.delete_one({"_id": converted_id}, session=session)
            log_admin_action(user, "delete", collection_name, {"deleted_data": original_document})
            messagebox.showinfo("Success", "Entry deleted successfully!")
            tree.delete(selected_item)  # Remove from TreeView

            # Commit the transaction
            session.commit_transaction()
        except Exception as e:
            # Rollback the transaction if anything fails
            session.abort_transaction()
            messagebox.showerror("Error", f"Failed to delete entry. Rolled back to original state.\n{str(e)}")

# Function to create the main GUI and display data in tabs (for admin only)
def create_gui(user):
    print("Starting the data insertion process...")
    insert_default_data_from_csv()  # Insert data into MongoDB if collections are empty

    print("\nExporting collections to backup CSV files...")
    export_to_csv()  # Export collections to CSV files after insertion

    print("\nProcess completed successfully.")
    root = Tk()
    root.title(f"{db_name} Database Test")

    def on_close():
        # Release the admin lock
        logout_or_exit(user)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    Label(root, text="Admin Dashboard").pack()
    Button(root, text="Exit", command=on_close).pack()

    # Create a Notebook widget for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')

    # Add all collection tabs and the Search tab for admin
    for collection_name in db.list_collection_names():
        collection = db[collection_name]
        documents = list(collection.find())
        columns = list(documents[0].keys()) if documents else []

        frame = ttk.Frame(notebook)
        notebook.add(frame, text=collection_name)

        tree = ttk.Treeview(frame, columns=columns, show='headings')
        tree.pack(expand=True, fill='both')

        for column in columns:
            tree.heading(column, text=column, anchor="center",
                         command=lambda c=column, cn=collection_name, t=tree: sort_column_click(None, cn, t, c))
            tree.column(column, anchor="center", width=100)

        for document in documents:
            values = [document.get(column, "") for column in columns]
            tree.insert("", "end", values=values, iid=str(document["_id"]))

        button_frame = Frame(frame)
        button_frame.pack(fill='x', padx=5, pady=5)

        # Add, Update, Delete buttons
        Button(button_frame, text="Add Entry",
               command=lambda cn=collection_name, t=tree, cols=columns: add_entry(cn, t, cols, user)).pack(side=LEFT, padx=5)
        Button(button_frame, text="Update Entry",
               command=lambda cn=collection_name, t=tree, cols=columns: update_entry(cn, t, cols, user)).pack(side=LEFT, padx=5)
        Button(button_frame, text="Delete Entry",
               command=lambda cn=collection_name, t=tree: delete_entry(cn, t, user)).pack(side=LEFT, padx=5)

    # Add the Search tab for the admin
    create_search_tab(notebook)
    root.mainloop()


create_login_screen()
