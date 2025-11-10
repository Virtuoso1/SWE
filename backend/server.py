# server.py
from flask import Flask, jsonify # type: ignore
from flask_cors import CORS # type: ignore

# Import blueprints
#from routes.users import users_bp
from books.books import books_bp
#from routes.borrows import borrows_bp
#from routes.fines import fines_bp
#from routes.dashboard import dashboard_bp

app = Flask(__name__)
CORS(app)

# Register blueprints
#app.register_blueprint(users_bp)
app.register_blueprint(books_bp)
#app.register_blueprint(borrows_bp)
#app.register_blueprint(fines_bp)
#app.register_blueprint(dashboard_bp)

@app.route('/')
def home():
    return jsonify({"message": "Library API is running "})

if __name__ == '__main__':
    app.run(debug=True)
