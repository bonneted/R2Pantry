from flask import Flask, render_template, url_for, flash, redirect, request, abort, session
from flask_sqlalchemy import SQLAlchemy
from models import db,User, PantryItem, Consumption
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PantryItemForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('+')

class ConsumptionForm(FlaskForm):
    item_id = SelectField('Item', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Register Consumption')

    def __init__(self, *args, **kwargs):
        super(ConsumptionForm, self).__init__(*args, **kwargs)
        self.item_id.choices = [(item.id, item.title) for item in PantryItem.query.all()]

def calculate_expenses(user_id):
    consumptions = Consumption.query.filter_by(user_id=user_id).all()
    total_expense = sum(item.item.price * item.quantity for item in consumptions)
    return total_expense


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pantry.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)

with app.app_context():
    db.create_all()

bcrypt = Bcrypt(app)
# csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set up Flask-Admin
admin = Admin(app, name='R2Pantry', template_mode='bootstrap3')
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(PantryItem, db.session))
admin.add_view(ModelView(Consumption, db.session))



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/", methods=['GET', 'POST'])
def home():
    login_form = LoginForm()
    registration_form = RegistrationForm()
    pantry_items = get_pantry_items()

    pantry_item_form = PantryItemForm()
    if pantry_item_form.validate_on_submit():
        add_new_pantry_item(pantry_item_form)
        pantry_items = get_pantry_items()

    if pantry_item_form.errors:
        flash_form_errors(pantry_item_form)

    all_users = User.query.order_by(User.username).all() if current_user.is_authenticated and current_user.is_admin else []

    if current_user.is_authenticated:
        user_to_edit_id = current_user.id

        if current_user.is_admin and 'user_to_edit_id' in session:
            user_to_edit_id = session['user_to_edit_id']

        detailed_expenses, total_expense = get_expenses(user_to_edit_id)
        user_to_edit = User.query.get(user_to_edit_id)

        return render_template('home.html', login_form=login_form, registration_form=registration_form, pantry_items=pantry_items, expenses=detailed_expenses, total_expense=total_expense, pantry_item_form=pantry_item_form, all_users=all_users, user_to_edit=user_to_edit)
    else:
        return render_template('home.html', login_form=login_form, registration_form=registration_form, pantry_items=pantry_items, pantry_item_form=pantry_item_form, all_users=all_users)

def get_pantry_items():
    return db.session.query(
        PantryItem,
        db.func.sum(Consumption.quantity).label('total_consumption')
    ).outerjoin(Consumption, PantryItem.id == Consumption.item_id) \
    .group_by(PantryItem.id) \
    .order_by(db.desc('total_consumption')) \
    .all()

def add_new_pantry_item(form):
    new_item = PantryItem(title=form.title.data, price=form.price.data)
    db.session.add(new_item)
    db.session.commit()
    flash('New pantry item added!', 'success')

def flash_form_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'Error in the {getattr(form, field).label.text} field - {error}', 'danger')

def get_expenses(user_to_edit_id):
    consumptions = db.session.query(
        PantryItem.title,
        db.func.sum(Consumption.quantity).label('total_quantity'),
        PantryItem.price
    ).join(PantryItem).filter(Consumption.user_id == user_to_edit_id).group_by(PantryItem.title, PantryItem.price).all()

    total_expense = 0
    detailed_expenses = []

    for title, total_quantity, price in consumptions:
        total_price = total_quantity * price
        total_expense += total_price
        detailed_expenses.append({
            'title': title,
            'quantity': total_quantity,
            'price_per_item': price,
            'total_price': total_price
        })

    return detailed_expenses, total_expense


@app.route("/purchase_item/<int:item_id>", methods=["POST"])
@login_required
def purchase_item(item_id):
    if current_user.is_admin and 'user_to_edit_id' in session:
        user_to_edit_id = session['user_to_edit_id']
    else:
        user_to_edit_id = current_user.id
    new_consumption = Consumption(user_id=user_to_edit_id, item_id=item_id, quantity=1)
    db.session.add(new_consumption)
    db.session.commit()
    flash('Item purchased successfully', 'success')
    return redirect(url_for('home'))

@app.route("/delete_item/<int:item_id>", methods=["POST"])
@login_required
def delete_item(item_id):
    if current_user.is_admin and 'user_to_edit_id' in session:
        user_to_edit_id = session['user_to_edit_id']
        print(user_to_edit_id)
        print(current_user.id)
    else:
        user_to_edit_id = current_user.id
    # Find the most recent consumption record for this item and user
    consumption_record = Consumption.query.filter_by(
        user_id=user_to_edit_id, item_id=item_id
    ).order_by(Consumption.timestamp.desc()).first()

    if consumption_record:
        db.session.delete(consumption_record)
        db.session.commit()
        flash('Item removed successfully', 'success')
    else:
        flash('No item to remove', 'warning')

    return redirect(url_for('home'))


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, password=hashed_password, is_admin=form.username.data == 'admin')
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'danger')
            
    return redirect(url_for('home', _anchor='registerModal'))

    



@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    login_form = LoginForm()
    registration_form = RegistrationForm()  # If needed for the base template

    if login_form.validate_on_submit():
        user = User.query.filter_by(username=login_form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, login_form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return redirect(url_for('home', _anchor='loginModal'))


@app.route("/logout")
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

@app.route('/set_user_to_edit', methods=['POST'])
@login_required
def set_user_to_edit():
    if not current_user.is_admin:
        abort(403)

    session['user_to_edit_id'] = request.form.get('user_id')
    return redirect(request.referrer or url_for('home'))


if __name__ == '__main__':
    app.run(debug=False)
