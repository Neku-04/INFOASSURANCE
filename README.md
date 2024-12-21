# EcoTrack

EcoTrack is a web application designed to manage food inventory efficiently. Built using Flask, it provides robust features for user authentication, profile management, and inventory control.

## Features
- User Authentication and Authorization
- Profile Management
- Food Inventory Management
- User Approval System
- Admin Dashboard
- Food Item Management (Add, Update, Delete)
- Profile Picture Upload

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/Neku-04/ecotrack.git
   cd ecotrack
   ```

2. Create a virtual environment and activate it:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```

4. Set up the database:
   - Ensure you have MySQL installed and running.
   - Create a database named `food_inventory`.
   - Update the `db_config` in `app.py` with your MySQL credentials.

5. Run the application:
   ```sh
   python app.py
   ```

6. Open your web browser and navigate to `http://127.0.0.1:5000`.

## Usage

### Registering a New User
- Navigate to the Register page and fill out the registration form.
- Upload a profile picture (PNG, JPG, JPEG, or GIF).
- Submit the form and wait for admin approval.

### Logging In
- Navigate to the Login page and enter your credentials.
- If approved, you will be redirected to the dashboard.

### Managing Food Items (Admin)
- Add new food items using the form on the dashboard.
- Update or delete existing food items from the list.

### Approving Users (Admin)
- Navigate to the Approve Users page to view pending user registrations.
- Approve or delete users as needed.

### Viewing and Updating Profile
- Navigate to the Profile page to view and update your profile information.
- Upload a new profile picture if desired.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
