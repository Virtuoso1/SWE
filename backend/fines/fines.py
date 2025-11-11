from flask import Flask, request, jsonify
from models import db, Fine

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fines.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# ------------------------
# ROUTE 1: Get user fines
# ------------------------
@app.route('/fine', methods=['GET'])
def get_user_fines():
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    fines = Fine.query.filter_by(user_id=user_id).all()
    return jsonify([fine.to_dict() for fine in fines])

# ------------------------
# ROUTE 2: Mark fine as paid
# ------------------------
@app.route('/pay', methods=['POST'])
def mark_fine_as_paid():
    data = request.get_json()
    fine_id = data.get('fine_id')

    if not fine_id:
        return jsonify({'error': 'fine_id is required'}), 400

    fine = Fine.query.get(fine_id)

    if not fine:
        return jsonify({'error': 'Fine not found'}), 404

    fine.status = 'paid'
    db.session.commit()

    return jsonify({'message': 'Fine marked as paid successfully'})

# ------------------------
# Run the Flask app
# ------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if not exist
    app.run(debug=True)
