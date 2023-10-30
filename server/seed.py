from app import db, create_app
from models import User, Role, Organization, Beneficiary, Donation, Story, Inventory
from datetime import datetime
app = create_app()

def seed_data():
    # Create Roles
    admin_role = Role.query.filter_by(name='Admin').first()
    if not admin_role:
        admin_role = Role(name='Admin')
        db.session.add(admin_role)

    user_role = Role.query.filter_by(name='User').first()
    if not user_role:
        user_role = Role(name='User')
        db.session.add(user_role)

    # Create Admin User
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@example.com', password='adminpass')
        admin.roles.append(admin_role)
        db.session.add(admin)
        db.session.commit()

     # Create Organization User
    org_user = User.query.filter_by(username='orguser').first()
    if not org_user:
        org_user = User(username='orguser', email='orguser@example.com', password='orgpass')
        org_user.roles.append(user_role)  # Assuming you want the organization user to also have the "User" role
        db.session.add(org_user)    
    
    # Create Donor User
    donor = User.query.filter_by(username='donor').first()
    if not donor:
        donor = User(username='donor', email='donor@example.com', password='donorpass')
        donor.roles.append(user_role)  # Assuming you want the donor to have the "User" role
        db.session.add(donor)

    # Create Organizations
    organization_1 = Organization.query.filter_by(name='Organization 1').first()
    if not organization_1:
        organization_1 = Organization(user_id=admin.id, name='Organization 1', description='Description for organization 1')
        db.session.add(organization_1)

    organization_2 = Organization.query.filter_by(name='Organization 2').first()
    if not organization_2:
        organization_2 = Organization(user_id=admin.id, name='Organization 2', description='Description for organization 2')
        db.session.add(organization_2)

    # Create Beneficiaries
    beneficiary_1 = Beneficiary.query.filter_by(name='Beneficiary 1').first()
    if not beneficiary_1:
        beneficiary_1 = Beneficiary(name='Beneficiary 1', description='Description for beneficiary 1', organization_id=organization_1.id)
        db.session.add(beneficiary_1)

    beneficiary_2 = Beneficiary.query.filter_by(name='Beneficiary 2').first()
    if not beneficiary_2:
        beneficiary_2 = Beneficiary(name='Beneficiary 2', description='Description for beneficiary 2', organization_id=organization_2.id)
        db.session.add(beneficiary_2)

     # Create Donations
    donation_1 = Donation.query.filter_by(amount=100.00).first()
    if not donation_1:
        donation_1 = Donation(donor_user_id=admin.id, organization_id=organization_1.id, amount=100.00, donation_type='Cash', anonymous=False, date=datetime.today().date())
        db.session.add(donation_1)

    donation_2 = Donation.query.filter_by(amount=50.00).first()
    if not donation_2:
        donation_2 = Donation(donor_user_id=admin.id, organization_id=organization_2.id, amount=50.00, donation_type='Goods', anonymous=True, date=datetime.today().date())
        db.session.add(donation_2)    

     # Create Stories
    story_1 = Story.query.filter_by(title='Story 1').first()
    if not story_1:
        story_1 = Story(organization_id=organization_1.id, title='Story 1', content='Content for story 1', date_created=datetime.today().date())
        db.session.add(story_1)

    story_2 = Story.query.filter_by(title='Story 2').first()
    if not story_2:
        story_2 = Story(organization_id=organization_2.id, title='Story 2', content='Content for story 2', date_created=datetime.today().date())
        db.session.add(story_2)    

    # Create Inventory items for Beneficiaries
    inventory_1 = Inventory.query.filter_by(description='Item 1').first()
    if not inventory_1:
        inventory_1 = Inventory(beneficiary_id=beneficiary_1.id, description='Item 1', quantity=10, date_received=datetime.today().date())
        db.session.add(inventory_1)

    inventory_2 = Inventory.query.filter_by(description='Item 2').first()
    if not inventory_2:
        inventory_2 = Inventory(beneficiary_id=beneficiary_2.id, description='Item 2', quantity=5, date_received=datetime.today().date())
        db.session.add(inventory_2)
    # Commit changes to the database
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        seed_data()
