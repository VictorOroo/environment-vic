from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from flask_migrate import Migrate
import os
from database import db
from models import User, Role, Organization, Donation, Story, Beneficiary, Inventory
from datetime import datetime

def create_app():
  app = Flask(__name__)

  app.config['SECRET_KEY'] = '9UCo3DbQZw'
  DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///mazingira.db')
  app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL

  db.init_app(app)
  migrate = Migrate(app, db)

  def decode_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.filter_by(username=data['username']).first()
        return current_user
    except Exception as e:
        app.logger.error(f"Token decode error: {e}")
        return None

  def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        current_user = decode_token(token)
        if not current_user:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

  def is_admin(user):
    return user.has_role('admin')

  @app.route('/')
  def index():
    return "Welcome to the Mazingira Application!"


  @app.route('/login', methods=['POST'])
  def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400

    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']):
        token = jwt.encode({'username': user.username}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    else:
        return jsonify({'message': 'Invalid credentials'})

  @app.route('/admin', methods=['GET'])
  @token_required
  def admin_route(current_user):
    if is_admin(current_user):
        return jsonify({'message': 'Welcome, admin!'})
    else:
        return jsonify({'message': 'Unauthorized'})
    
  @app.route('/users', methods=['POST'])
  @token_required
  def create_user(current_user):
    if not current_user.is_admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    data = request.get_json()

    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400

    existing_user_by_name = User.query.filter_by(username=data['username']).first()
    existing_user_by_email = User.query.filter_by(email=data['email']).first()

    if existing_user_by_name or existing_user_by_email:
        return jsonify({'message': 'Username or Email already exists'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(new_user.to_dict()), 201 
    except Exception as e:
        app.logger.error(f"Error creating user: {e}")
        return jsonify({'message': 'Error creating user'}), 500


  @app.route('/users/<int:user_id>', methods=['DELETE'])
  @token_required
  def delete_user(current_user, user_id):
    # Ensure the admin is not trying to delete their own account
    if current_user.id == user_id:
        return jsonify({'message': 'You cannot delete your own account!'}), 403

    if not current_user.is_admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'No user found!'}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'The user has been deleted!'})
    except Exception as e:
        app.logger.error(f"Error deleting user: {e}")
        return jsonify({'message': 'Error deleting user'}), 500
    
# @app.route('/users/profile', methods=['PUT'])
# @token_required
# def update_own_profile(current_user):
#     data = request.get_json()     
#     if not data:
#         return jsonify({'message': 'No data provided'}), 400    
#     if 'username' in data:
#         existing_user = User.query.filter_by(username=data['username']).first()
#         if existing_user and existing_user.id != current_user.id:
#             return jsonify({'message': 'Username is already taken'}), 400
#         current_user.username = data['username'] 
#     if 'email' in data:
#         current_user.email = data['email']
#     try:        
#         db.session.commit()
#         return jsonify({'message': 'Profile updated successfully'})
#     except Exception as e:
#         app.logger.error(f"Error updating profile: {e}")
#         return jsonify({'message': 'Error updating profile'}), 500

  @app.route('/users/<int:user_id>/profile', methods=['PATCH'])
  @token_required
  def edit_user_profile(current_user, user_id):
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({'message': 'Cannot edit another user\'s profile'}), 401
    
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'No user found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    # Edit username if provided in request data
    if 'username' in data:
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'message': 'Username is already taken'}), 400
        user.username = data['username']

    # Edit email if provided in request data
    if 'email' in data:
        user.email = data['email']

    try:
        # Commit the changes to the database
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})
    except Exception as e:
        app.logger.error(f"Error updating profile: {e}")
        return jsonify({'message': 'Error updating profile'}), 500
               #admin routes
  @app.route('/admin/organization-requests', methods=['GET'])
  @token_required
  def view_organization_requests(current_user):
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 403

    pending_organizations = Organization.query.filter_by(is_approved=False).all()
    serialized_organizations = [org.to_dict() for org in pending_organizations]

    return jsonify(serialized_organizations)

  @app.route('/admin/organization-approve/<int:org_id>', methods=['POST'])
  @token_required
  def approve_organization(current_user, org_id):
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 403

    organization = Organization.query.get(org_id)
    if not organization:
        return jsonify({'message': 'Organization not found'}), 404

    organization.is_approved = True
    db.session.commit()

    serialized_organization = organization.to_dict()
    
    return jsonify({'message': f'Organization {organization.name} approved!', 'organization': serialized_organization})

  @app.route('/admin/organization-reject/<int:org_id>', methods=['POST'])
  @token_required
  def reject_organization(current_user, org_id):
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 403

    organization = Organization.query.get(org_id)
    if not organization:
        return jsonify({'message': 'Organization not found'}), 404

    db.session.delete(organization)
    db.session.commit()

    return jsonify({'message': f'Organization {organization.name} rejected and deleted!'})
              #orgaization routes 
  @app.route('/organizations', methods=['POST'])
  @token_required
  def create_organization(current_user):
    data = request.get_json()

    # Check for input data
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    # Validate essential information
    if not data.get('name'):
        return jsonify({'message': 'Organization name is required'}), 400

    new_organization = Organization(
        user_id=current_user.id,
        name=data.get('name'),
        description=data.get('description', ''),  # default to an empty string if not provided
        contact_information=data.get('contact_information', ''),  # default to an empty string if not provided
        status="Pending"  # default status
    )

    db.session.add(new_organization)
    db.session.commit()
    return jsonify({'message': 'Organization application submitted successfully'}), 201

  @app.route('/organizations', methods=['GET'])
  def list_organizations():
    organizations = Organization.query.filter_by(status='Approved').all()
    return jsonify([org.serialize() for org in organizations])

  @app.route('/organizations/<int:org_id>', methods=['GET'])
  def get_organization(org_id):
    organization = Organization.query.get_or_404(org_id)
    return jsonify(organization.serialize())

  @app.route('/organizations/<int:org_id>', methods=['PUT'])
  @token_required
  def update_organization(current_user, org_id):
    organization = Organization.query.get_or_404(org_id)
    if current_user.id != organization.user_id and not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.get_json()
    if data:
        organization.name = data.get('name', organization.name)
        organization.description = data.get('description', organization.description)
        organization.contact_information = data.get('contact_information', organization.contact_information)
        db.session.commit()
        return jsonify({'message': 'Organization updated successfully'}), 200
    else:
        return jsonify({'message': 'No input data provided'}), 400
  @app.route('/organizations/<int:org_id>', methods=['PATCH'])
  @token_required
  def patch_organization(current_user, org_id):
    organization = Organization.query.get_or_404(org_id)
    if current_user.id != organization.user_id and not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.get_json()
    if data:
        organization.name = data.get('name', organization.name)
        organization.description = data.get('description', organization.description)
        organization.contact_information = data.get('contact_information', organization.contact_information)
        db.session.commit()
        return jsonify({'message': 'Organization details updated successfully'}), 200
    else:
        return jsonify({'message': 'No input data provided'}), 400

  @app.route('/organizations/<int:org_id>', methods=['DELETE'])
  @token_required
  def delete_organization(current_user, org_id):
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 401

    organization = Organization.query.get_or_404(org_id)
    db.session.delete(organization)
    db.session.commit()
    return jsonify({'message': 'Organization deleted successfully'}), 200
          #donation routes
  @app.route('/donations', methods=['POST'])
  @token_required
  def create_donation(current_user):
    data = request.get_json()

    if not data.get('organization_id') or not data.get('amount') or not data.get('donation_type') or not data.get('date'):
        return jsonify({'message': 'Missing mandatory fields'}), 400

    organization = Organization.query.get(data['organization_id'])

    if not organization:
        return jsonify({'message': 'Organization not found'}), 404

    donation = Donation(
        donor_user_id=current_user.id,
        organization_id=data['organization_id'],
        amount=data['amount'],
        donation_type=data['donation_type'],
        date=data['date'],
        anonymous=data.get('anonymous', False)
    )

    db.session.add(donation)
    db.session.commit()

    return jsonify({'message': 'Donation added successfully'}), 201


  @app.route('/donations', methods=['GET'])
  @token_required
  def get_donations(current_user):
    donations = Donation.query.filter_by(donor_user_id=current_user.id).all()
    return jsonify([d.serialize() for d in donations])


  @app.route('/donations/<int:donation_id>', methods=['GET'])
  @token_required
  def get_donation(current_user, donation_id):
    donation = Donation.query.get(donation_id)

    if not donation:
        return jsonify({'message': 'Donation not found'}), 404

    if donation.donor_user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    return jsonify(donation.serialize())


  @app.route('/donations/<int:donation_id>', methods=['PATCH'])
  @token_required
  def modify_donation(current_user, donation_id):
    data = request.get_json()
    donation = Donation.query.get(donation_id)

    if not donation:
        return jsonify({'message': 'Donation not found'}), 404

    if donation.donor_user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    if data.get('amount'):
        donation.amount = data['amount']
    if data.get('donation_type'):
        donation.donation_type = data['donation_type']
    if data.get('anonymous'):
        donation.anonymous = data['anonymous']

    db.session.commit()

    return jsonify({'message': 'Donation updated successfully'})
          #story routes
  @app.route('/stories', methods=['POST'])
  @token_required
  def create_story(current_user):
    data = request.get_json()

    if not data.get('organization_id') or not data.get('title') or not data.get('content'):
        return jsonify({'message': 'Missing mandatory fields'}), 400

    organization = Organization.query.get(data['organization_id'])
    
    if not organization or organization.user_id != current_user.id:
        return jsonify({'message': 'Organization not found or permission denied'}), 404

    story = Story(
        organization_id=data['organization_id'],
        title=data['title'],
        content=data['content'],
        date_created=datetime.utcnow()  # Assuming date_created is auto-generated when a story is created
    )

    db.session.add(story)
    db.session.commit()

    return jsonify({'message': 'Story added successfully'}), 201


  @app.route('/stories', methods=['GET'])
  def get_stories():
    stories = Story.query.all()
    return jsonify([s.serialize() for s in stories])


  @app.route('/stories/<int:story_id>', methods=['GET'])
  def get_story(story_id):
    story = Story.query.get(story_id)

    if not story:
        return jsonify({'message': 'Story not found'}), 404

    return jsonify(story.serialize())
       #beneficiary routes
  @app.route('/beneficiaries', methods=['POST'])
  @token_required
  def create_beneficiary(current_user):
    data = request.get_json()

    if not data.get('organization_id') or not data.get('name'):
        return jsonify({'message': 'Missing mandatory fields'}), 400

    organization = Organization.query.get(data['organization_id'])

    # Check if the organization exists and if the current user is associated with the organization
    if not organization or organization.user_id != current_user.id:
        return jsonify({'message': 'Organization not found or permission denied'}), 404

    beneficiary = Beneficiary(
        organization_id=data['organization_id'],
        name=data['name']
    )

    db.session.add(beneficiary)
    db.session.commit()

    return jsonify({'message': 'Beneficiary added successfully'}), 201


  @app.route('/beneficiaries', methods=['GET'])
  @token_required
  def get_beneficiaries(current_user):
    organization_ids = [org.id for org in current_user.organizations]  # Assuming a backref from User to Organization

    beneficiaries = Beneficiary.query.filter(Beneficiary.organization_id.in_(organization_ids)).all()
    return jsonify([b.serialize() for b in beneficiaries])


  @app.route('/beneficiaries/<int:beneficiary_id>', methods=['GET'])
  @token_required
  def get_beneficiary(beneficiary_id, current_user):
    beneficiary = Beneficiary.query.get(beneficiary_id)

    if not beneficiary:
        return jsonify({'message': 'Beneficiary not found'}), 404

    if beneficiary.organization.user_id != current_user.id:  # Checking if the beneficiary belongs to the authenticated user's organization
        return jsonify({'message': 'Access denied'}), 403

    return jsonify(beneficiary.serialize())
   #inventory routes
  @app.route('/inventory', methods=['POST'])
  @token_required
  def add_inventory(current_user):
    data = request.get_json()

    if not data.get('beneficiary_id') or not data.get('description') or not data.get('quantity') or not data.get('date_received'):
        return jsonify({'message': 'Missing mandatory fields'}), 400

    beneficiary = Beneficiary.query.get(data['beneficiary_id'])

    # Check if the beneficiary exists and if the organization associated with the beneficiary is tied to the current user
    if not beneficiary or beneficiary.organization.user_id != current_user.id:
        return jsonify({'message': 'Beneficiary not found or permission denied'}), 404

    inventory_item = Inventory(
        beneficiary_id=data['beneficiary_id'],
        description=data['description'],
        quantity=data['quantity'],
        date_received=data['date_received']  #date_received is passed in 'YYYY-MM-DD' format
    )

    db.session.add(inventory_item)
    db.session.commit()

    return jsonify({'message': 'Inventory item added successfully'}), 201


  @app.route('/inventory', methods=['GET'])
  @token_required
  def get_inventory(current_user):
    organization_ids = [org.id for org in current_user.organizations]
    beneficiaries = Beneficiary.query.filter(Beneficiary.organization_id.in_(organization_ids)).all()

    beneficiary_ids = [b.id for b in beneficiaries]

    inventory_items = Inventory.query.filter(Inventory.beneficiary_id.in_(beneficiary_ids)).all()

    return jsonify([item.serialize() for item in inventory_items])


  @app.route('/inventory/<int:inventory_id>', methods=['GET'])
  @token_required
  def get_inventory_item(inventory_id, current_user):
    inventory_item = Inventory.query.get(inventory_id)

    if not inventory_item:
        return jsonify({'message': 'Inventory item not found'}), 404

    if inventory_item.beneficiary.organization.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403

    return jsonify(inventory_item.serialize())
  return app
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
