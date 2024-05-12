from flask import Flask, request, jsonify
import pymysql.cursors
from decimal import Decimal
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta


# Init app
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'cheia_secreta'  # Change this to a secret key
app.config['JWT_EXPIRATION_DELTA'] = timedelta(minutes=60)

jwt = JWTManager(app)
# Function to establish connection with MySQL database
# Example user model
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

# Example user database
users = {
    'username': User('username', 'password')
}

# User authentication function
def authenticate(username, password):
    user = users.get(username)
    if user and check_password_hash(user.password, password):
        return user

# Identity function for JWT
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username

# Error handler for JWT authentication failures
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return jsonify({'message': 'You shall not pass... without the Authorization Header!'}), 401


# Route for user login to generate JWT token
@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    user = authenticate(username, password)
    if user:
        access_token = create_access_token(identity=user)
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid username or password'}), 401
# Example protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

def get_db_connection():
    connection = pymysql.connect(host='localhost',
                                 user='root',
                                 password='proiect2024',
                                 db='sakila',
                                 cursorclass=pymysql.cursors.DictCursor)
    return connection

# Route to return all actors in the catalog
@app.route('/api/v2/resources/actors/', methods=['GET'])
def api_all_actors():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM actor;')
    all_actors = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for film in all_actors:
        for key, value in film.items():
            if isinstance(value, Decimal):
                film[key] = float(value)

    return jsonify(all_actors)

# Route to return all actors info in the catalog
@app.route('/api/v2/resources/actorinfo/', methods=['GET'])
def api_all_actorinfo():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM actor_info;')
    all_actorinfo = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for film in all_actorinfo:
        for key, value in film.items():
            if isinstance(value, Decimal):
                film[key] = float(value)

    return jsonify(all_actorinfo)

# Route to return all address in the catalog
@app.route('/api/v2/resources/address/', methods=['GET'])
def api_all_address():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT address_id, address, address2, district, city_id, postal_code, phone FROM address;')
    all_address = cur.fetchall()
    conn.close()
    # Convert Decimal types to float
    for address in all_address:
        for key, value in address.items():
            if isinstance(value, Decimal):
                address[key] = float(value)

    return jsonify(all_address)

# Route to return all category in the catalog
@app.route('/api/v2/resources/category/', methods=['GET'])
def api_all_category():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM category;')
    all_category = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for category in all_category:
        for key, value in category.items():
            if isinstance(value, Decimal):
                category[key] = float(value)

    return jsonify(all_category)

# Route to return all city in the catalog
@app.route('/api/v2/resources/city/', methods=['GET'])
def api_all_city():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM city;')
    all_city = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for film in all_city:
        for key, value in film.items():
            if isinstance(value, Decimal):
                film[key] = float(value)

    return jsonify(all_city)

# Route to return all country in the catalog
@app.route('/api/v2/resources/country/', methods=['GET'])
def api_all_country():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM country;')
    all_country = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for country in all_country:
        for key, value in country.items():
            if isinstance(value, Decimal):
                country[key] = float(value)

    return jsonify(all_country)


# Route to return all customer in the catalog
@app.route('/api/v2/resources/customer/', methods=['GET'])
def api_all_customer():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM customer;')
    all_customer = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for customer in all_customer:
        for key, value in customer.items():
            if isinstance(value, Decimal):
                customer[key] = float(value)

    return jsonify(all_customer)


# Route to return all customerlist in the catalog
@app.route('/api/v2/resources/customerlist/', methods=['GET'])
def api_all_customerlist():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM customer_list;')
    all_customerlist = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for customerlist in all_customerlist:
        for key, value in customerlist.items():
            if isinstance(value, Decimal):
                customerlist[key] = float(value)

    return jsonify(all_customerlist)

# Route to return all films in the catalog
@app.route('/api/v2/resources/films/', methods=['GET'])
def api_all_films():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM film;')
    all_films = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for film in all_films:
        for key, value in film.items():
            if isinstance(value, Decimal):
                film[key] = float(value)

    return jsonify(all_films)

# Route to return all filmactor in the catalog
@app.route('/api/v2/resources/filmactor/', methods=['GET'])
def api_all_filmactor():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM film_actor;')
    all_filmactor = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for filmactor in all_filmactor:
        for key, value in filmactor.items():
            if isinstance(value, Decimal):
                filmactor[key] = float(value)

    return jsonify(all_filmactor)

# Route to return all filmcategory in the catalog
@app.route('/api/v2/resources/filmcategory/', methods=['GET'])
def api_all_filmcategory():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM film_category;')
    all_filmcategory = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for filmcategory in all_filmcategory:
        for key, value in filmcategory.items():
            if isinstance(value, Decimal):
                filmcategory[key] = float(value)

    return jsonify(all_filmcategory)

# Route to return all filmlist in the catalog
@app.route('/api/v2/resources/filmlist/', methods=['GET'])
def api_all_filmlist():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM film_list;')
    all_filmlist = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for filmlist in all_filmlist:
        for key, value in filmlist.items():
            if isinstance(value, Decimal):
                filmlist[key] = float(value)

    return jsonify(all_filmlist)

# Route to return all filmtext in the catalog
@app.route('/api/v2/resources/filmtext/', methods=['GET'])
def api_all_filmtext():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM film_text;')
    all_filmtext = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for filmtext in all_filmtext:
        for key, value in filmtext.items():
            if isinstance(value, Decimal):
                filmtext[key] = float(value)

    return jsonify(all_filmtext)

# Route to return all inventory in the catalog
@app.route('/api/v2/resources/inventory/', methods=['GET'])
def api_all_inventory():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM inventory;')
    all_inventory = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for inventory in all_inventory:
        for key, value in inventory.items():
            if isinstance(value, Decimal):
                inventory[key] = float(value)

    return jsonify(all_inventory)

# Route to return all language in the catalog
@app.route('/api/v2/resources/language/', methods=['GET'])
def api_all_language():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM language;')
    all_language = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for language in all_language:
        for key, value in language.items():
            if isinstance(value, Decimal):
                language[key] = float(value)

    return jsonify(all_language)

# Route to return all nicerbutslower in the catalog
@app.route('/api/v2/resources/nicerbutslower/', methods=['GET'])
def api_all_nicerbutslower():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM nicer_but_slower_film_list ;')
    all_nicerbutslower = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for nicerbutslower in all_nicerbutslower:
        for key, value in nicerbutslower.items():
            if isinstance(value, Decimal):
                nicerbutslower[key] = float(value)

    return jsonify(all_nicerbutslower)

# Route to return all payment in the catalog
@app.route('/api/v2/resources/payment/', methods=['GET'])
def api_all_payment():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM payment;')
    all_payment = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for payment in all_payment:
        for key, value in payment.items():
            if isinstance(value, Decimal):
                payment[key] = float(value)

    return jsonify(all_payment)
# Route to return all rental in the catalog
@app.route('/api/v2/resources/rental/', methods=['GET'])
def api_all_rental():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM rental;')
    all_rental = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for rental in all_rental:
        for key, value in rental.items():
            if isinstance(value, Decimal):
                rental[key] = float(value)

    return jsonify(all_rental)

# Route to return all salesbyfilmcategory in the catalog
@app.route('/api/v2/resources/salesbyfilmcategory/', methods=['GET'])
def api_all_salesbyfilmcategory():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM sales_by_film_category;')
    all_salesbyfilmcategory = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for salesbyfilmcategory in all_salesbyfilmcategory:
        for key, value in salesbyfilmcategory.items():
            if isinstance(value, Decimal):
                salesbyfilmcategory[key] = float(value)

    return jsonify(all_salesbyfilmcategory)

# Route to return all salesbystore in the catalog
@app.route('/api/v2/resources/salesbystore/', methods=['GET'])
def api_all_salesbystore():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM sales_by_store;')
    all_salesbystore = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for salesbystore in all_salesbystore:
        for key, value in salesbystore.items():
            if isinstance(value, Decimal):
                salesbystore[key] = float(value)

    return jsonify(all_salesbystore)

# Route to return all staff in the catalog
@app.route('/api/v2/resources/staff/', methods=['GET'])
def api_all_staff():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT staff_id, first_name, last_name, address_id, email, store_id, active, username, password, last_update FROM staff;')
    all_staff = cur.fetchall()
    conn.close()
    print(all_staff)
    # Convert Decimal types to float
    for staff in all_staff:
        for key, value in staff.items():
            if isinstance(value, Decimal):
                staff[key] = float(value)

    return jsonify(all_staff)

# Route to return all stafflist in the catalog
@app.route('/api/v2/resources/stafflist/', methods=['GET'])
def api_all_stafflist():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM staff_list;')
    all_stafflist = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for stafflist in all_stafflist:
        for key, value in stafflist.items():
            if isinstance(value, Decimal):
                stafflist[key] = float(value)

    return jsonify(all_stafflist)

@app.route('/api/v2/resources/store/', methods=['GET'])
def api_all_store():

    # Extract JWT token from the URL query parameters
    token = request.args.get('token')
    try:
        decoded_token = decode_token(token)
        # Check token expiration
        if datetime.fromtimestamp(decoded_token['exp']) < datetime.now():
            return jsonify({'message': 'Token has expired'}), 401
        # Additional validation checks if needed
        # e.g., verify user roles, permissions, etc.
    except Exception as e:
        return jsonify({'message': 'Invalid token'}), 401

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM store;')
    all_store = cur.fetchall()
    conn.close()

    # Convert Decimal types to float
    for store in all_store:
        for key, value in store.items():
            if isinstance(value, Decimal):
                store[key] = float(value)

    return jsonify(all_store)

# Error handler for 404
@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404 - Not Found</h1><p>You've stumbled into Fight Club's 404 Error Room. First rule of browsing: don't talk about the missing page!</p>", 404

# A method that runs the application server.
if __name__ == "__main__":
    # Threaded option to enable multiple instances for multiple user access support
    app.run(debug=False, threaded=True, port=5000)
