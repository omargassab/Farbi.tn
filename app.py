# Farbi.tn - Flask App with Profiles, Cart, Order History, User Mgmt, etc.
# Added User Profiles (view designs).
# Added Shopping Cart (session-based) & Checkout (creates multiple orders).
# Added User Order History page.

import os
import uuid
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   abort, send_from_directory, session, jsonify) # Added session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps # For custom decorators if needed

# --- Configuration ---

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
# IMPORTANT: Use a strong, randomly generated secret key in production!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'a-very-secret-key-keep-it-safe-and-change-it-for-sessions'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'instance', 'farbi.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # 50 MB upload limit
app.config['ORDERS_PER_PAGE'] = 15
app.config['USERS_PER_PAGE'] = 15

ALLOWED_DESIGN_EXTENSIONS = {'stl', 'obj', '3mf'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

# Order Status Constants (remain the same)
ORDER_STATUS_RECEIVED = 'received'; ORDER_STATUS_PRINTING = 'printing'; ORDER_STATUS_PACKAGING = 'packaging'
ORDER_STATUS_DELIVERING = 'out_for_delivery'; ORDER_STATUS_DELIVERED = 'delivered'; ORDER_STATUS_FAILED = 'failed_delivery'
ORDER_STATUS_CANCELLED = 'cancelled'
ORDER_STATUSES = [ORDER_STATUS_RECEIVED, ORDER_STATUS_PRINTING, ORDER_STATUS_PACKAGING, ORDER_STATUS_DELIVERING, ORDER_STATUS_DELIVERED, ORDER_STATUS_FAILED, ORDER_STATUS_CANCELLED]

try:
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except OSError as e: print(f"Error creating directories: {e}")

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Flask-Login Setup ---
login_manager = LoginManager(); login_manager.init_app(app)
login_manager.login_view = 'login'; login_manager.login_message_category = 'info'
@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- Helper Functions ---
def allowed_file(filename, allowed_extensions): return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
def generate_unique_filename(filename, user_id):
    _, ext = os.path.splitext(filename); timestamp = int(datetime.utcnow().timestamp()); secure_name = secure_filename(filename)
    max_len_original = 50; truncated_name = secure_name[:max_len_original] if len(secure_name) > max_len_original else secure_name
    unique_name = f"user_{user_id}_{timestamp}_{truncated_name}{ext}"; return unique_name

# --- Models (User model updated) ---
favorites = db.Table('favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('design_id', db.Integer, db.ForeignKey('design.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_designer = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    # New profile fields
    bio = db.Column(db.Text, nullable=True)
    join_date = db.Column(db.DateTime, default=datetime.utcnow)
    # Relationships
    designs = db.relationship('Design', backref='designer', lazy='dynamic')
    orders = db.relationship('Order', backref='customer', lazy='dynamic')
    favorite_designs = db.relationship('Design', secondary=favorites, lazy='dynamic', backref=db.backref('favorited_by', lazy='dynamic'))

    def __repr__(self): return f'<User {self.username}>'
    def set_password(self, password): self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    def check_password(self, password): return check_password_hash(self.password_hash, password)
    def add_favorite(self, design):
        if not self.is_favorite(design): self.favorite_designs.append(design)
    def remove_favorite(self, design):
        if self.is_favorite(design): self.favorite_designs.remove(design)
    def is_favorite(self, design): return self.favorite_designs.filter(favorites.c.design_id == design.id).count() > 0

class Design(db.Model):
    # ... (remains the same as previous version) ...
    id = db.Column(db.Integer, primary_key=True); title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True); file_path = db.Column(db.String(300), nullable=False)
    image_path = db.Column(db.String(300), nullable=True); status = db.Column(db.String(20), default='pending', nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow); designer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    royalty_amount = db.Column(db.Float, default=5.0)
    def __repr__(self): return f'<Design {self.title}>'

class Order(db.Model):
    # ... (remains the same as previous version) ...
    id = db.Column(db.Integer, primary_key=True); order_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(30), default=ORDER_STATUS_RECEIVED, nullable=False); customer_name = db.Column(db.String(100), nullable=False)
    customer_address = db.Column(db.Text, nullable=False); customer_phone = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True); design_id = db.Column(db.Integer, db.ForeignKey('design.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False); design = db.relationship('Design')
    def __repr__(self): return f'<Order {self.id} - Design {self.design_id}>'

# --- Context Processors (For Cart Count) ---
@app.context_processor
def inject_cart_count():
    """ Makes cart item count available to all templates """
    cart = session.get('cart', {})
    item_count = sum(cart.values()) if cart else 0
    return dict(cart_item_count=item_count)

@app.context_processor
def inject_now():
    """ Make datetime available to all templates """
    return {'now': datetime.utcnow}

# --- Authentication Routes ---
# (Register, Login, Logout routes remain the same)
@app.route('/register', methods=['GET', 'POST'])
def register():
    # ... (same as before) ...
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username'); email = request.form.get('email'); password = request.form.get('password'); confirm_password = request.form.get('confirm_password'); is_designer = request.form.get('is_designer') == 'on'
        if not username or not email or not password or not confirm_password: flash('All fields except "Register as Designer" are required.', 'danger'); return redirect(url_for('register'))
        if password != confirm_password: flash('Passwords do not match.', 'danger'); return redirect(url_for('register'))
        if User.query.filter_by(username=username).first(): flash('Username already exists. Please choose another.', 'warning'); return redirect(url_for('register'))
        if User.query.filter_by(email=email).first(): flash('Email address already registered. Please use another.', 'warning'); return redirect(url_for('register'))
        new_user = User(username=username, email=email, is_designer=is_designer); new_user.set_password(password)
        db.session.add(new_user); db.session.commit(); login_user(new_user)
        flash(f'Registration successful! Welcome, {new_user.username}!', 'success'); return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (same as before) ...
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        identifier = request.form.get('identifier'); password = request.form.get('password'); remember = request.form.get('remember') == 'on'
        if not identifier or not password: flash('Username/Email and Password are required.', 'danger'); return redirect(url_for('login'))
        user = User.query.filter_by(email=identifier).first();
        if not user: user = User.query.filter_by(username=identifier).first()
        if user and user.check_password(password):
            login_user(user, remember=remember); flash(f'Logged in successfully as {user.username}.', 'success')
            next_page = request.args.get('next'); return redirect(next_page or url_for('index'))
        else: flash('Invalid username/email or password.', 'danger'); return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # ... (same as before) ...
    logout_user(); flash('You have been logged out.', 'info'); return redirect(url_for('index'))

# --- Core Application Routes ---
@app.route('/')
def index():
    # ... (same as before) ...
    featured_designs = Design.query.filter_by(status='approved').order_by(Design.upload_date.desc()).limit(4).all()
    return render_template('index.html', featured_designs=featured_designs)

@app.route('/browse')
def browse():
    # ... (same as before) ...
    all_approved_designs = Design.query.filter_by(status='approved').order_by(Design.upload_date.desc()).all()
    return render_template('browse.html', designs=all_approved_designs)

# --- NEW: User Profile Route ---
@app.route('/profile/<username>')
def profile(username):
    """ Displays a user's public profile page """
    user = User.query.filter_by(username=username).first_or_404()
    # Fetch user's approved designs if they are a designer
    user_designs = []
    if user.is_designer:
        user_designs = user.designs.filter_by(status='approved').order_by(Design.upload_date.desc()).all()
    # Sales count calculation deferred for simplicity
    return render_template('profile.html', user=user, designs=user_designs)

@app.route('/design/<int:design_id>')
def design_detail(design_id):
    # ... (same as before, but now includes Add to Cart button) ...
    design = Design.query.get_or_404(design_id)
    can_view = False
    if design.status == 'approved': can_view = True
    elif current_user.is_authenticated and (current_user.id == design.designer_id or current_user.is_admin): can_view = True
    if not can_view: abort(404)
    print_cost_placeholder = 10.00; service_fee_placeholder = 3.00
    final_price = (design.royalty_amount or 0.0) + print_cost_placeholder + service_fee_placeholder
    is_favorite = current_user.is_favorite(design) if current_user.is_authenticated else False
    # Check if item is in cart (optional, for button state)
    cart = session.get('cart', {})
    in_cart = str(design_id) in cart
    return render_template('design_detail.html', design=design, final_price=final_price, is_favorite=is_favorite, in_cart=in_cart)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_design():
    # ... (same file saving logic as before) ...
    if not current_user.is_designer: flash('Only registered designers can upload designs.', 'warning'); return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form.get('title'); description = request.form.get('description'); royalty_str = request.form.get('royalty_amount', '5.0')
        if 'design_file' not in request.files: flash('No design file part in the request.', 'danger'); return redirect(request.url)
        design_file = request.files['design_file']; image_file = request.files.get('image_file')
        if design_file.filename == '': flash('No selected design file.', 'danger'); return redirect(request.url)
        if design_file and allowed_file(design_file.filename, ALLOWED_DESIGN_EXTENSIONS):
            try: 
                royalty_amount = float(royalty_str);
                if royalty_amount < 0: raise ValueError("Royalty cannot be negative.")
            except ValueError: flash('Invalid royalty amount entered.', 'danger'); return redirect(request.url)
            design_filename = generate_unique_filename(design_file.filename, current_user.id)
            design_save_path = os.path.join(app.config['UPLOAD_FOLDER'], design_filename); image_filename = None
            if image_file and image_file.filename != '' and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                image_filename = generate_unique_filename(image_file.filename, current_user.id)
                image_save_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            elif image_file and image_file.filename != '': flash('Invalid image file type. Allowed types: png, jpg, jpeg, webp.', 'warning'); image_filename = None
            try:
                design_file.save(design_save_path); print(f"Saved design file: {design_save_path}")
                if image_filename: image_file.save(image_save_path); print(f"Saved image file: {image_save_path}")
                new_design = Design(title=title, description=description, file_path=design_filename, image_path=image_filename, designer_id=current_user.id, royalty_amount=royalty_amount, status='pending');
                db.session.add(new_design); db.session.commit()
                flash(f'Design "{title}" uploaded successfully! It is pending admin approval.', 'success'); return redirect(url_for('index'))
            except Exception as e: db.session.rollback(); print(f"Error during upload: {e}"); flash('An error occurred during the upload process. Please try again.', 'danger'); return redirect(request.url)
        else: flash('Invalid design file type. Allowed types: stl, obj, 3mf.', 'danger'); return redirect(request.url)
    return render_template('upload.html')

# --- Cart Routes ---

@app.route('/cart/add/<int:design_id>', methods=['POST'])
def add_to_cart(design_id):
    """ Adds an item to the cart stored in the session """
    design = Design.query.get_or_404(design_id)
    if design.status != 'approved':
        flash('This design cannot be added to the cart.', 'warning')
        return redirect(request.referrer or url_for('browse'))

    cart = session.get('cart', {}) # Get cart or initialize empty dict
    design_id_str = str(design_id) # Use strings for session keys

    quantity = cart.get(design_id_str, 0) + 1 # Increment quantity
    cart[design_id_str] = quantity

    session['cart'] = cart # Save cart back to session
    session.modified = True # Mark session as modified

    flash(f'"{design.title}" added to your cart.', 'success')
    # Return JSON response if request prefers it (for potential AJAX updates later)
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
         return jsonify(success=True, item_count=sum(cart.values()))
    return redirect(request.referrer or url_for('browse')) # Redirect back

@app.route('/cart/remove/<int:design_id>', methods=['POST'])
def remove_from_cart(design_id):
    """ Removes an item completely from the cart """
    cart = session.get('cart', {})
    design_id_str = str(design_id)

    if design_id_str in cart:
        del cart[design_id_str]
        session['cart'] = cart
        session.modified = True
        flash('Item removed from cart.', 'info')
    else:
        flash('Item not found in cart.', 'warning')

    return redirect(url_for('view_cart'))

@app.route('/cart/update/<int:design_id>', methods=['POST'])
def update_cart_item(design_id):
    """ Updates the quantity of an item in the cart """
    cart = session.get('cart', {})
    design_id_str = str(design_id)

    try:
        new_quantity = int(request.form.get('quantity', 0))
    except ValueError:
        flash('Invalid quantity specified.', 'danger')
        return redirect(url_for('view_cart'))

    if design_id_str in cart:
        if new_quantity > 0:
            cart[design_id_str] = new_quantity
            flash('Cart updated.', 'success')
        elif new_quantity <= 0: # Treat 0 or less as removal
            del cart[design_id_str]
            flash('Item removed from cart.', 'info')
        session['cart'] = cart
        session.modified = True
    else:
        flash('Item not found in cart.', 'warning')

    return redirect(url_for('view_cart'))


@app.route('/cart')
def view_cart():
    """ Displays the contents of the shopping cart """
    cart = session.get('cart', {})
    cart_items = []
    grand_total = 0.0

    if cart:
        design_ids = [int(id_str) for id_str in cart.keys()]
        designs = Design.query.filter(Design.id.in_(design_ids)).all()
        design_map = {design.id: design for design in designs} # For easy lookup

        for design_id_str, quantity in cart.items():
            design_id = int(design_id_str)
            design = design_map.get(design_id)
            if design:
                # --- Placeholder for Price Calculation ---
                print_cost_placeholder = 10.00
                service_fee_placeholder = 3.00
                item_price = (design.royalty_amount or 0.0) + print_cost_placeholder + service_fee_placeholder
                # --- End Placeholder ---
                total_item_price = item_price * quantity
                grand_total += total_item_price
                cart_items.append({
                    'design': design,
                    'quantity': quantity,
                    'item_price': item_price,
                    'total_item_price': total_item_price
                })
            else:
                # Handle case where a design ID in cart no longer exists or is invalid
                # Maybe remove it from the cart here?
                print(f"Warning: Design ID {design_id_str} found in cart but not in database.")
                pass # For now, just skip it

    return render_template('cart.html', cart_items=cart_items, grand_total=grand_total)


# --- Checkout and Order History ---

@app.route('/checkout', methods=['POST'])
def checkout():
    """ Processes the cart and creates orders (one per item for simplicity) """
    cart = session.get('cart', {})
    if not cart:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('view_cart'))

    # Get COD details from form
    customer_name = request.form.get('customer_name')
    customer_address = request.form.get('customer_address')
    customer_phone = request.form.get('customer_phone')

    if not customer_name or not customer_address or not customer_phone:
        flash('Please provide your name, address, and phone number for Cash on Delivery.', 'danger')
        return redirect(url_for('view_cart')) # Stay on cart page to fix info

    design_ids = [int(id_str) for id_str in cart.keys()]
    designs = Design.query.filter(Design.id.in_(design_ids)).all()
    design_map = {design.id: design for design in designs}

    orders_created_count = 0
    try:
        for design_id_str, quantity in cart.items():
            design_id = int(design_id_str)
            design = design_map.get(design_id)
            if design and design.status == 'approved': # Ensure design still exists and is approved
                # --- Placeholder for Price Calculation ---
                print_cost_placeholder = 10.00
                service_fee_placeholder = 3.00
                item_price = (design.royalty_amount or 0.0) + print_cost_placeholder + service_fee_placeholder
                # --- End Placeholder ---
                total_price = item_price * quantity # Total for this specific order line

                # Create a separate order for each item * quantity
                for _ in range(quantity):
                    new_order = Order(
                        customer_name=customer_name,
                        customer_address=customer_address,
                        customer_phone=customer_phone,
                        design_id=design.id,
                        total_price=item_price, # Price for a single item
                        user_id=current_user.id if current_user.is_authenticated else None,
                        status=ORDER_STATUS_RECEIVED
                    )
                    db.session.add(new_order)
                    orders_created_count += 1
            else:
                print(f"Skipping order for design ID {design_id} - not found or not approved.")
                flash(f"Item '{design.title if design else f'ID {design_id}'}' could not be ordered as it's no longer available.", 'warning')


        if orders_created_count > 0:
            db.session.commit()
            session.pop('cart', None) # Clear the cart after successful checkout
            session.modified = True
            flash(f'Your order has been placed successfully! ({orders_created_count} item(s)) We will contact you for confirmation (Cash on Delivery).', 'success')
            return redirect(url_for('order_history') if current_user.is_authenticated else url_for('index')) # Redirect to history or index
        else:
             flash('No items could be ordered. Please check your cart.', 'danger')
             return redirect(url_for('view_cart'))

    except Exception as e:
        db.session.rollback()
        print(f"Error during checkout: {e}")
        flash('An error occurred during checkout. Please try again.', 'danger')
        return redirect(url_for('view_cart'))

@app.route('/order_history')
@login_required
def order_history():
    """ Displays the current user's past orders """
    # Order by most recent first
    user_orders = current_user.orders.order_by(Order.order_date.desc()).all()
    return render_template('order_history.html', orders=user_orders)


# --- Favorites Routes ---
# (Add Favorite, Remove Favorite, List Favorites routes remain the same)
@app.route('/favorite/<int:design_id>', methods=['POST'])
@login_required
def add_favorite(design_id):
    # ... (same as before) ...
    design = Design.query.get_or_404(design_id)
    if design.status != 'approved': flash('Cannot favorite this design.', 'warning'); return redirect(request.referrer or url_for('index'))
    current_user.add_favorite(design); db.session.commit()
    flash(f'"{design.title}" added to your favorites!', 'success'); return redirect(request.referrer or url_for('index'))

@app.route('/unfavorite/<int:design_id>', methods=['POST'])
@login_required
def remove_favorite(design_id):
    # ... (same as before) ...
    design = Design.query.get_or_404(design_id); current_user.remove_favorite(design); db.session.commit()
    flash(f'"{design.title}" removed from your favorites.', 'info'); return redirect(request.referrer or url_for('index'))

@app.route('/favorites')
@login_required
def list_favorites():
    # ... (same as before) ...
    favorite_designs = current_user.favorite_designs.filter(Design.status == 'approved').all()
    return render_template('favorites.html', designs=favorite_designs)


# --- Admin Routes ---
# (Dashboard, User Mgmt, Order Mgmt, Design Mgmt routes remain the same)
@app.route('/admin')
@login_required
def admin_dashboard():
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    pending_count = Design.query.filter_by(status='pending').count(); order_count = Order.query.count(); user_count = User.query.count()
    return render_template('admin_dashboard.html', pending_count=pending_count, order_count=order_count, user_count=user_count)

@app.route('/admin/users')
@login_required
def admin_users():
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    page = request.args.get('page', 1, type=int)
    pagination = User.query.order_by(User.username.asc()).paginate(page=page, per_page=app.config['USERS_PER_PAGE'], error_out=False)
    users = pagination.items; return render_template('admin_users.html', users=users, pagination=pagination)

@app.route('/admin/user/<int:user_id>/details')
@login_required
def admin_user_details(user_id):
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    user = User.query.get_or_404(user_id); return render_template('admin_user_details.html', user=user)

@app.route('/admin/user/<int:user_id>/update_roles', methods=['POST'])
@login_required
def admin_update_user_roles(user_id):
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    user = User.query.get_or_404(user_id); new_is_designer = request.form.get('is_designer') == 'on'; new_is_admin = request.form.get('is_admin') == 'on'
    if user.id == current_user.id and not new_is_admin and user.is_admin: flash('You cannot remove your own administrator privileges.', 'danger'); return redirect(url_for('admin_user_details', user_id=user_id))
    roles_changed = False
    if user.is_designer != new_is_designer: user.is_designer = new_is_designer; roles_changed = True
    if user.is_admin != new_is_admin: user.is_admin = new_is_admin; roles_changed = True
    if roles_changed:
        try: db.session.commit(); flash(f'Roles updated successfully for user {user.username}.', 'success'); print(f"Admin Action: Updated roles for User ID {user_id} by {current_user.username}")
        except Exception as e: db.session.rollback(); print(f"Error updating user roles: {e}"); flash('An error occurred while updating roles.', 'danger')
    else: flash('No changes detected in roles.', 'info')
    return redirect(url_for('admin_user_details', user_id=user_id))

@app.route('/admin/orders')
@login_required
def admin_orders():
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    page = request.args.get('page', 1, type=int)
    pagination = Order.query.order_by(Order.order_date.desc()).paginate(page=page, per_page=app.config['ORDERS_PER_PAGE'], error_out=False)
    orders = pagination.items; return render_template('admin_orders.html', orders=orders, pagination=pagination)

@app.route('/admin/order/<int:order_id>/details')
@login_required
def admin_order_details(order_id):
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    order = Order.query.get_or_404(order_id); return render_template('admin_order_details.html', order=order, statuses=ORDER_STATUSES)

@app.route('/admin/order/<int:order_id>/update_status', methods=['POST'])
@login_required
def admin_update_order_status(order_id):
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    order = Order.query.get_or_404(order_id); new_status = request.form.get('status')
    if new_status and new_status in ORDER_STATUSES: order.status = new_status; db.session.commit(); flash(f'Order #{order.id} status updated to "{new_status}".', 'success'); print(f"Admin Action: Updated Order ID {order_id} status to {new_status} by {current_user.username}")
    else: flash('Invalid status selected.', 'danger')
    return redirect(url_for('admin_order_details', order_id=order_id))

@app.route('/admin/pending')
@login_required
def admin_pending_designs():
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    pending_designs = Design.query.filter_by(status='pending').order_by(Design.upload_date.asc()).all()
    return render_template('admin_pending.html', designs=pending_designs)

@app.route('/admin/design/<int:design_id>/details')
@login_required
def admin_design_details(design_id):
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    design = Design.query.get_or_404(design_id); return render_template('admin_design_details.html', design=design)

@app.route('/admin/approve/<int:design_id>', methods=['POST'])
@login_required
def admin_approve_design(design_id):
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    design = Design.query.get_or_404(design_id); design.status = 'approved'; db.session.commit()
    flash(f'Design "{design.title}" approved.', 'success'); print(f"Admin Action: Approved Design ID {design_id} by {current_user.username}")
    return redirect(url_for('admin_pending_designs'))

@app.route('/admin/reject/<int:design_id>', methods=['POST'])
@login_required
def admin_reject_design(design_id):
    # ... (same as before) ...
    if not current_user.is_admin: abort(403)
    design = Design.query.get_or_404(design_id); design.status = 'rejected'; db.session.commit()
    flash(f'Design "{design.title}" rejected.', 'warning'); print(f"Admin Action: Rejected Design ID {design_id} by {current_user.username}")
    return redirect(url_for('admin_pending_designs'))


# --- Route to Serve Uploaded Files ---
# (Remains the same)
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # ... (same as before) ...
    try:
        _, ext = os.path.splitext(filename)
        is_design_file = ext.lower().lstrip('.') in ALLOWED_DESIGN_EXTENSIONS
        is_image_file = ext.lower().lstrip('.') in ALLOWED_IMAGE_EXTENSIONS
        if is_design_file or is_image_file:
             return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=is_design_file)
        else: abort(404)
    except FileNotFoundError: abort(404)


# --- Template Files ---

# templates/base.html (Updated for Profile & Cart Links)
"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Farbi.tn{% endblock %} - 3D Printing Tunisia</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .nav-link { @apply text-gray-600 hover:text-indigo-600 transition duration-150 ease-in-out; }
        .nav-button { @apply px-4 py-2 rounded-lg text-sm font-medium transition duration-150 ease-in-out; }
        .nav-button-primary { @apply nav-button bg-indigo-600 text-white hover:bg-indigo-700; }
        .nav-button-secondary { @apply nav-button bg-green-500 text-white hover:bg-green-600; }
        .nav-button-logout { @apply nav-button bg-red-500 text-white hover:bg-red-600; }
        .favorite-btn { background: none; border: none; cursor: pointer; padding: 0.25rem; color: #9ca3af; transition: color 0.2s ease-in-out; }
        .favorite-btn.active { color: #ef4444; } .favorite-btn:hover { color: #f87171; } .favorite-btn.active:hover { color: #dc2626; }
        .cart-badge { @apply absolute -top-2 -right-2 bg-red-500 text-white text-xs font-bold rounded-full h-5 w-5 flex items-center justify-center; }
    </style>
</head>
<body class="bg-gray-100 text-gray-800 flex flex-col min-h-screen">

    <header class="bg-white shadow-md sticky top-0 z-50">
        <nav class="container mx-auto px-4 py-4 flex justify-between items-center">
            <a href="{{ url_for('index') }}" class="text-2xl font-bold text-indigo-600">Farbi.tn</a>
            <div class="flex items-center space-x-4">
                <a href="{{ url_for('browse') }}" class="nav-link hidden md:inline">Browse</a>
                {% if current_user.is_authenticated %}
                    <a href="{{ url_for('list_favorites') }}" class="nav-link hidden md:inline" title="My Favorites"><i class="fas fa-heart"></i></a>
                    <a href="{{ url_for('profile', username=current_user.username) }}" class="nav-link hidden md:inline" title="My Profile"><i class="fas fa-user"></i></a>
                    <a href="{{ url_for('order_history') }}" class="nav-link hidden md:inline" title="Order History"><i class="fas fa-history"></i></a>
                    {% if current_user.is_designer %} <a href="{{ url_for('upload_design') }}" class="nav-button-secondary hidden md:inline">Upload</a> {% endif %}
                    {% if current_user.is_admin %} <a href="{{ url_for('admin_dashboard') }}" class="nav-link hidden md:inline font-semibold text-purple-600">Admin</a> {% endif %}
                    <span class="text-gray-700 text-sm hidden lg:inline">Hi, {{ current_user.username }}!</span>
                    <a href="{{ url_for('logout') }}" class="nav-button-logout">Logout</a>
                {% else %}
                    <a href="{{ url_for('login') }}" class="nav-button-primary">Login</a>
                    <a href="{{ url_for('register') }}" class="nav-link">Register</a>
                {% endif %}
                 <a href="{{ url_for('view_cart') }}" class="nav-link relative" title="Shopping Cart">
                    <i class="fas fa-shopping-cart text-xl"></i>
                    {% if cart_item_count > 0 %} <span class="cart-badge">{{ cart_item_count }}</span> {% endif %}
                 </a>
                 <button id="mobile-menu-button" class="md:hidden text-gray-600 hover:text-indigo-600 focus:outline-none"> <i class="fas fa-bars text-xl"></i> </button>
            </div>
        </nav>
    </header>

    <div class="container mx-auto px-4 pt-4 w-full max-w-4xl"> {# Flash Messages Container #}
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %} {% for category, message in messages %}
                    <div class="p-4 mb-4 text-sm rounded-lg shadow {% if category == 'danger' %} bg-red-100 text-red-800 border border-red-200 {% elif category == 'success' %} bg-green-100 text-green-800 border border-green-200 {% elif category == 'warning' %} bg-yellow-100 text-yellow-800 border border-yellow-200 {% else %} bg-blue-100 text-blue-800 border border-blue-200 {% endif %}" role="alert">
                        <i class="fas {% if category == 'danger' %}fa-exclamation-triangle{% elif category == 'success' %}fa-check-circle{% elif category == 'warning' %}fa-exclamation-circle{% else %}fa-info-circle{% endif %} mr-2"></i> {{ message }}
                    </div>
            {% endfor %} {% endif %}
        {% endwith %}
    </div>

    <main class="container mx-auto px-4 py-8 flex-grow"> {% block content %}{% endblock %} </main>

    <footer class="bg-gray-800 text-gray-300 mt-auto"> <div class="container mx-auto px-4 py-8 text-center"> <p class="text-sm">&copy; {{ now().year }} Farbi.tn. All rights reserved.</p> </div> </footer>
    {% block scripts %}{% endblock %}
</body>
</html>
"""

# templates/register.html (No changes needed)
""" ... (content remains the same) ... """
# templates/login.html (No changes needed)
""" ... (content remains the same) ... """
# templates/upload.html (No changes needed)
""" ... (content remains the same) ... """

# templates/index.html (Updated Designer Link)
"""
{% extends "base.html" %}
{% block title %}Homepage{% endblock %}
{% block content %}
<section class="bg-gradient-to-r from-indigo-500 to-purple-600 text-white rounded-lg shadow-xl p-8 md:p-12 mb-12 text-center">
    <h1 class="text-3xl md:text-5xl font-bold mb-4">Farbi.tn: 3D Printing Made Local</h1>
    <p class="text-lg md:text-xl mb-6">Discover unique designs from Tunisian creators. We print and deliver via COD.</p>
    <div class="flex justify-center space-x-4">
        <a href="{{ url_for('browse') }}" class="bg-white text-indigo-700 px-6 py-3 rounded-lg font-semibold hover:bg-gray-100 transition duration-200">Explore Designs</a>
        {% if current_user.is_authenticated and current_user.is_designer %}
            <a href="{{ url_for('upload_design') }}" class="bg-transparent border-2 border-white text-white px-6 py-3 rounded-lg font-semibold hover:bg-white hover:text-indigo-700 transition duration-200">Upload Your Design</a>
        {% elif not current_user.is_authenticated %}
             <a href="{{ url_for('register') }}" class="bg-transparent border-2 border-white text-white px-6 py-3 rounded-lg font-semibold hover:bg-white hover:text-indigo-700 transition duration-200">Become a Designer</a>
        {% endif %}
    </div>
</section>

<section class="mb-12">
    <h2 class="text-2xl font-semibold mb-6 text-gray-700">Featured Designs</h2>
    {% if featured_designs %}
    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
        {% for design in featured_designs %}
        <div class="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition-shadow duration-200 relative">
            <a href="{{ url_for('design_detail', design_id=design.id) }}">
                <div class="aspect-square bg-gray-200 flex items-center justify-center">
                    {% if design.image_path %} <img src="{{ url_for('uploaded_file', filename=design.image_path) }}" alt="{{ design.title }} Preview" class="object-cover w-full h-full">
                    {% else %} <span class="text-gray-500 text-sm">No Preview</span> {% endif %}
                </div>
            </a>
            <div class="p-4">
                 <a href="{{ url_for('design_detail', design_id=design.id) }}"> <h3 class="font-semibold text-lg mb-1 truncate">{{ design.title }}</h3> </a>
                 {# Link designer name to profile #}
                 <p class="text-sm text-gray-500 mb-2">By <a href="{{ url_for('profile', username=design.designer.username) }}" class="text-indigo-600 hover:underline">{{ design.designer.username }}</a></p>
                 <a href="{{ url_for('design_detail', design_id=design.id) }}"> <p class="text-gray-700 mb-3 text-sm truncate">{{ design.description or 'No description available.' }}</p> </a>
                <div class="flex justify-between items-center">
                    <span class="font-bold text-indigo-600">{{ "%.2f TND"|format(design.royalty_amount + 13.0) }}</span> {# Example Price #}
                    {% if current_user.is_authenticated %}
                        {% if current_user.is_favorite(design) %} <form action="{{ url_for('remove_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn active" title="Remove from Favorites"><i class="fas fa-heart text-lg"></i></button></form>
                        {% else %} <form action="{{ url_for('add_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn" title="Add to Favorites"><i class="far fa-heart text-lg"></i></button></form> {% endif %}
                    {% else %} <a href="{{ url_for('login', next=request.url) }}" class="favorite-btn" title="Login to Favorite"><i class="far fa-heart text-lg"></i></a> {% endif %}
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
    {% else %} <p class="text-gray-600">No featured designs available yet.</p> {% endif %}
</section>
{% endblock %}
"""

# templates/browse.html (Updated Designer Link)
"""
{% extends "base.html" %}
{% block title %}Browse Designs{% endblock %}
{% block content %}
<h1 class="text-3xl font-semibold mb-8 text-gray-800">All Approved Designs</h1>
{% if designs %}
<div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
    {% for design in designs %}
    <div class="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition-shadow duration-200 relative">
        <a href="{{ url_for('design_detail', design_id=design.id) }}">
            <div class="aspect-square bg-gray-200 flex items-center justify-center">
                 {% if design.image_path %} <img src="{{ url_for('uploaded_file', filename=design.image_path) }}" alt="{{ design.title }} Preview" class="object-cover w-full h-full">
                {% else %} <span class="text-gray-500 text-sm">No Preview</span> {% endif %}
            </div>
        </a>
        <div class="p-4">
             <a href="{{ url_for('design_detail', design_id=design.id) }}"> <h3 class="font-semibold text-lg mb-1 truncate">{{ design.title }}</h3> </a>
             {# Link designer name to profile #}
             <p class="text-sm text-gray-500 mb-2">By <a href="{{ url_for('profile', username=design.designer.username) }}" class="text-indigo-600 hover:underline">{{ design.designer.username }}</a></p>
             <a href="{{ url_for('design_detail', design_id=design.id) }}"> <p class="text-gray-700 mb-3 text-sm truncate">{{ design.description or 'No description available.' }}</p> </a>
            <div class="flex justify-between items-center">
                <span class="font-bold text-indigo-600">{{ "%.2f TND"|format(design.royalty_amount + 13.0) }}</span> {# Example Price #}
                {% if current_user.is_authenticated %}
                    {% if current_user.is_favorite(design) %} <form action="{{ url_for('remove_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn active" title="Remove from Favorites"><i class="fas fa-heart text-lg"></i></button></form>
                    {% else %} <form action="{{ url_for('add_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn" title="Add to Favorites"><i class="far fa-heart text-lg"></i></button></form> {% endif %}
                {% else %} <a href="{{ url_for('login', next=request.url) }}" class="favorite-btn" title="Login to Favorite"><i class="far fa-heart text-lg"></i></a> {% endif %}
            </div>
        </div>
    </div>
    {% endfor %}
</div>
{% else %} <p class="text-gray-600">No designs found.</p> {% endif %}
{% endblock %}
"""

# templates/design_detail.html (Updated Designer Link & Add to Cart Button)
"""
{% extends "base.html" %}
{% block title %}{{ design.title }}{% endblock %}
{% block content %}
<div class="bg-white p-6 md:p-8 rounded-lg shadow-lg">
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div> {# Image Column #}
            <div class="aspect-square bg-gray-200 rounded-lg flex items-center justify-center mb-4">
                 {% if design.image_path %} <img src="{{ url_for('uploaded_file', filename=design.image_path) }}" alt="{{ design.title }} Preview" class="object-contain w-full h-full rounded-lg">
                 {% else %} <span class="text-gray-500 text-lg">No Preview Available</span> {% endif %}
            </div>
        </div>
        <div> {# Details Column #}
            <div class="flex justify-between items-start mb-2">
                 <h1 class="text-3xl font-bold text-gray-900">{{ design.title }}</h1>
                 {% if design.status == 'approved' %} {# Favorite Button #}
                    {% if current_user.is_authenticated %}
                        {% if is_favorite %} <form action="{{ url_for('remove_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn active text-2xl" title="Remove from Favorites"><i class="fas fa-heart"></i></button></form>
                        {% else %} <form action="{{ url_for('add_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn text-2xl" title="Add to Favorites"><i class="far fa-heart"></i></button></form> {% endif %}
                    {% else %} <a href="{{ url_for('login', next=request.url) }}" class="favorite-btn text-2xl" title="Login to Favorite"><i class="far fa-heart"></i></a> {% endif %}
                 {% endif %}
            </div>
            {# Link designer name to profile #}
            <p class="text-sm text-gray-500 mb-4">By <a href="{{ url_for('profile', username=design.designer.username) }}" class="text-indigo-600 hover:underline">{{ design.designer.username }}</a></p>
            {% if design.status == 'pending' %} <p class="mb-4 p-2 rounded bg-yellow-100 text-yellow-800 text-sm border border-yellow-200">Status: Pending Approval</p>
            {% elif design.status == 'rejected' %} <p class="mb-4 p-2 rounded bg-red-100 text-red-800 text-sm border border-red-200">Status: Rejected</p>
            {% endif %}
            <p class="text-gray-700 mb-6">{{ design.description or 'No description provided.' }}</p>
            <div class="mb-6">
                <span class="text-3xl font-bold text-indigo-600">{{ "%.2f TND"|format(final_price) }}</span>
                <span class="text-sm text-gray-500 ml-2">(Price includes printing & delivery)</span>
            </div>

            {# Add to Cart Button (Replaces Order Form) #}
            {% if design.status == 'approved' %}
            <form action="{{ url_for('add_to_cart', design_id=design.id) }}" method="POST">
                 <button type="submit" class="w-full bg-indigo-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-indigo-700 transition duration-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 flex items-center justify-center">
                    <i class="fas fa-cart-plus mr-2"></i> Add to Cart
                 </button>
            </form>
            {% else %}
             <button disabled class="w-full bg-gray-400 text-white px-6 py-3 rounded-lg font-semibold cursor-not-allowed flex items-center justify-center">
                 <i class="fas fa-times-circle mr-2"></i> Not Available
             </button>
            {% endif %}
        </div>
    </div>
</div>
{% endblock %}
"""

# templates/favorites.html (No changes needed)
""" ... (content remains the same) ... """
# templates/admin_dashboard.html (No changes needed)
""" ... (content remains the same) ... """
# templates/admin_users.html (Updated Designer Link)
"""
{% extends "base.html" %}
{% block title %}Admin - Manage Users{% endblock %}
{% block content %}
<div class="flex justify-between items-center mb-8"> <h1 class="text-3xl font-semibold text-gray-800">Manage Users</h1> </div>
{% if users %}
<div class="bg-white shadow-md rounded-lg overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50"> <tr> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Username</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th> <th scope="col" class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Designer?</th> <th scope="col" class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Admin?</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th> </tr> </thead>
        <tbody class="bg-white divide-y divide-gray-200">
            {% for user in users %} <tr class="{% if user.id == current_user.id %} bg-indigo-50 {% endif %}">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ user.id }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900"> <a href="{{ url_for('profile', username=user.username) }}" class="hover:underline" target="_blank">{{ user.username }}</a> </td> {# Link to profile #}
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ user.email }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-center"> {% if user.is_designer %} <i class="fas fa-check-circle text-green-500"></i> {% else %} <i class="fas fa-times-circle text-gray-400"></i> {% endif %} </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-center"> {% if user.is_admin %} <i class="fas fa-user-shield text-purple-600"></i> {% else %} <i class="fas fa-times-circle text-gray-400"></i> {% endif %} </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium"> <a href="{{ url_for('admin_user_details', user_id=user.id) }}" class="text-indigo-600 hover:text-indigo-900">Edit Roles</a> </td>
            </tr> {% endfor %}
        </tbody>
    </table>
</div>
{# Pagination (remains same) #}
{% if pagination and (pagination.has_prev or pagination.has_next) %} <nav class="mt-6 flex items-center justify-between border-t border-gray-200 px-4 sm:px-0"> <div class="flex w-0 flex-1"> {% if pagination.has_prev %} <a href="{{ url_for('admin_users', page=pagination.prev_num) }}" class="inline-flex items-center border-t-2 border-transparent pr-1 pt-4 text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700"> <i class="fas fa-arrow-left mr-3 h-5 w-5 text-gray-400"></i> Previous </a> {% endif %} </div> <div class="hidden md:flex"> {% for page_num in pagination.iter_pages() %} {% if page_num %} {% if page_num != pagination.page %} <a href="{{ url_for('admin_users', page=page_num) }}" class="inline-flex items-center border-t-2 border-transparent px-4 pt-4 text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700">{{ page_num }}</a> {% else %} <a href="#" class="inline-flex items-center border-t-2 border-indigo-500 px-4 pt-4 text-sm font-medium text-indigo-600" aria-current="page">{{ page_num }}</a> {% endif %} {% else %} <span class="inline-flex items-center border-t-2 border-transparent px-4 pt-4 text-sm font-medium text-gray-500">...</span> {% endif %} {% endfor %} </div> <div class="flex w-0 flex-1 justify-end"> {% if pagination.has_next %} <a href="{{ url_for('admin_users', page=pagination.next_num) }}" class="inline-flex items-center border-t-2 border-transparent pl-1 pt-4 text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700"> Next <i class="fas fa-arrow-right ml-3 h-5 w-5 text-gray-400"></i> </a> {% endif %} </div> </nav> {% endif %}
{% else %} <p class="text-gray-600 text-center mt-10">No users found.</p> {% endif %}
{% endblock %}
"""

# templates/admin_user_details.html (Updated Designer Link)
"""
{% extends "base.html" %}
{% block title %}Admin User Details: {{ user.username }}{% endblock %}
{% block content %}
<div class="bg-white p-6 md:p-8 rounded-lg shadow-lg max-w-2xl mx-auto">
    <div class="flex justify-between items-start mb-6 border-b pb-4">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">{{ user.username }}</h1>
            <p class="text-sm text-gray-500 mt-1">{{ user.email }}</p>
            <p class="text-xs text-gray-400 mt-1">User ID: {{ user.id }} | Joined: {{ user.join_date.strftime('%Y-%m-%d') if user.join_date else 'N/A' }}</p>
             <p class="mt-2"><a href="{{ url_for('profile', username=user.username) }}" class="text-indigo-600 hover:underline text-sm" target="_blank">View Public Profile <i class="fas fa-external-link-alt text-xs ml-1"></i></a></p> {# Link to profile #}
        </div>
    </div>
    <form action="{{ url_for('admin_update_user_roles', user_id=user.id) }}" method="POST">
        <h2 class="text-xl font-semibold mb-4 text-gray-800">Manage Roles</h2>
        <div class="space-y-4">
            <div> <label class="flex items-center cursor-pointer"> <input type="checkbox" name="is_designer" class="rounded border-gray-300 text-indigo-600 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 h-5 w-5" {% if user.is_designer %}checked{% endif %}> <span class="ml-3 text-sm text-gray-700 font-medium">Designer Role</span> </label> <p class="text-xs text-gray-500 ml-8">Allows user to upload designs.</p> </div>
            <div> <label class="flex items-center {% if user.id == current_user.id %} cursor-not-allowed opacity-70 {% else %} cursor-pointer {% endif %}"> <input type="checkbox" name="is_admin" class="rounded border-gray-300 text-purple-600 shadow-sm focus:border-purple-300 focus:ring focus:ring-purple-200 focus:ring-opacity-50 h-5 w-5" {% if user.is_admin %}checked{% endif %} {% if user.id == current_user.id %}disabled title="Cannot remove your own admin role"{% endif %}> <span class="ml-3 text-sm text-gray-700 font-medium">Administrator Role</span> </label> <p class="text-xs text-gray-500 ml-8">Grants access to all admin areas.</p> {% if user.id == current_user.id %} <p class="text-xs text-red-600 ml-8 mt-1">You cannot revoke your own admin status.</p> {% endif %} </div>
        </div>
        <div class="mt-6 border-t pt-5"> <button type="submit" class="px-5 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 transition duration-150 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"> Save Role Changes </button> </div>
    </form>
    <div class="mt-8 border-t pt-6"> <a href="{{ url_for('admin_users') }}" class="text-indigo-600 hover:text-indigo-800 text-sm"> <i class="fas fa-arrow-left mr-1"></i> Back to All Users </a> </div>
</div>
{% endblock %}
"""

# templates/admin_pending.html (No changes needed)
""" ... (content remains the same) ... """
# templates/admin_design_details.html (Updated Designer Link)
"""
{% extends "base.html" %}
{% block title %}Admin Details: {{ design.title }}{% endblock %}
{% block content %}
<div class="bg-white p-6 md:p-8 rounded-lg shadow-lg">
    <div class="flex justify-between items-start mb-6">
        <div>
            <h1 class="text-3xl font-bold text-gray-900">{{ design.title }}</h1>
            <p class="text-sm text-gray-500 mt-1"> Uploaded by <a href="{{ url_for('profile', username=design.designer.username) }}" class="text-indigo-600 hover:underline">{{ design.designer.username }}</a> on {{ design.upload_date.strftime('%Y-%m-%d %H:%M') }} </p> {# Link to profile #}
             <p class="mt-2 p-2 inline-block rounded text-sm {% if design.status == 'pending' %} bg-yellow-100 text-yellow-800 border border-yellow-200 {% elif design.status == 'approved' %} bg-green-100 text-green-800 border border-green-200 {% elif design.status == 'rejected' %} bg-red-100 text-red-800 border border-red-200 {% endif %}"> Status: {{ design.status|capitalize }} </p>
        </div>
        {% if design.status == 'pending' %} <div class="flex space-x-3"> <form action="{{ url_for('admin_approve_design', design_id=design.id) }}" method="POST"> <button type="submit" class="px-4 py-2 rounded-lg text-sm font-medium bg-green-600 text-white hover:bg-green-700 transition duration-150 ease-in-out"> <i class="fas fa-check mr-1"></i> Approve </button> </form> <form action="{{ url_for('admin_reject_design', design_id=design.id) }}" method="POST"> <button type="submit" class="px-4 py-2 rounded-lg text-sm font-medium bg-red-600 text-white hover:bg-red-700 transition duration-150 ease-in-out"> <i class="fas fa-times mr-1"></i> Reject </button> </form> </div> {% endif %}
    </div>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
        <div class="md:col-span-1"> <h2 class="text-xl font-semibold mb-3 text-gray-800">Preview Image</h2> {% if design.image_path %} <img src="{{ url_for('uploaded_file', filename=design.image_path) }}" alt="{{ design.title }} Preview" class="w-full rounded-lg shadow border border-gray-200 object-contain"> {% else %} <div class="w-full aspect-square bg-gray-100 rounded-lg flex items-center justify-center text-gray-500 border"> No preview image uploaded. </div> {% endif %} </div>
        <div class="md:col-span-2"> <h2 class="text-xl font-semibold mb-3 text-gray-800">Design Information</h2> <div class="space-y-4"> <div> <label class="block text-sm font-medium text-gray-500">Description</label> <p class="mt-1 text-gray-800 bg-gray-50 p-3 rounded border">{{ design.description or 'No description provided.' }}</p> </div> <div> <label class="block text-sm font-medium text-gray-500">Designer Royalty</label> <p class="mt-1 text-gray-800">{{ "%.2f TND"|format(design.royalty_amount) }}</p> </div> <div> <label class="block text-sm font-medium text-gray-500">Design File</label> <a href="{{ url_for('uploaded_file', filename=design.file_path) }}" class="mt-1 inline-flex items-center px-3 py-1.5 border border-transparent text-sm leading-4 font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500" download> <i class="fas fa-download mr-2"></i> Download {{ design.file_path.split('.')[-1]|upper }} File </a> <p class="text-xs text-gray-500 mt-1">Filename: {{ design.file_path }}</p> </div> </div> </div>
    </div>
    <div class="mt-8 border-t pt-6"> <a href="{{ url_for('admin_pending_designs') }}" class="text-indigo-600 hover:text-indigo-800 text-sm"> <i class="fas fa-arrow-left mr-1"></i> Back to Pending Designs </a> </div>
</div>
{% endblock %}
"""

# templates/admin_orders.html (Updated Designer Link)
"""
{% extends "base.html" %}
{% block title %}Admin - Manage Orders{% endblock %}
{% block content %}
<div class="flex justify-between items-center mb-8"> <h1 class="text-3xl font-semibold text-gray-800">Manage Orders</h1> </div>
{% if orders %}
<div class="bg-white shadow-md rounded-lg overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50"> <tr> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Customer</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Design</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Total (TND)</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th> <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th> </tr> </thead>
        <tbody class="bg-white divide-y divide-gray-200">
            {% for order in orders %} <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#{{ order.id }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ order.order_date.strftime('%Y-%m-%d') }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ order.customer_name }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 truncate max-w-xs" title="{{ order.design.title }}"> <a href="{{ url_for('design_detail', design_id=order.design_id) }}" class="hover:underline" target="_blank"> {{ order.design.title }} (#{{ order.design_id }}) </a> </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700 font-medium">{{ "%.2f"|format(order.total_price) }}</td>
                <td class="px-6 py-4 whitespace-nowrap"> <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full {% if order.status == 'delivered' %} bg-green-100 text-green-800 {% elif order.status == 'cancelled' or order.status == 'failed_delivery' %} bg-red-100 text-red-800 {% elif order.status == 'out_for_delivery' %} bg-blue-100 text-blue-800 {% elif order.status == 'printing' or order.status == 'packaging' %} bg-yellow-100 text-yellow-800 {% else %} bg-gray-100 text-gray-800 {% endif %}"> {{ order.status.replace('_', ' ')|capitalize }} </span> </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium"> <a href="{{ url_for('admin_order_details', order_id=order.id) }}" class="text-indigo-600 hover:text-indigo-900">View Details</a> </td>
            </tr> {% endfor %}
        </tbody>
    </table>
</div>
{# Pagination (remains same) #}
{% if pagination and (pagination.has_prev or pagination.has_next) %} <nav class="mt-6 flex items-center justify-between border-t border-gray-200 px-4 sm:px-0"> <div class="flex w-0 flex-1"> {% if pagination.has_prev %} <a href="{{ url_for('admin_orders', page=pagination.prev_num) }}" class="inline-flex items-center border-t-2 border-transparent pr-1 pt-4 text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700"> <i class="fas fa-arrow-left mr-3 h-5 w-5 text-gray-400"></i> Previous </a> {% endif %} </div> <div class="hidden md:flex"> {% for page_num in pagination.iter_pages() %} {% if page_num %} {% if page_num != pagination.page %} <a href="{{ url_for('admin_orders', page=page_num) }}" class="inline-flex items-center border-t-2 border-transparent px-4 pt-4 text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700">{{ page_num }}</a> {% else %} <a href="#" class="inline-flex items-center border-t-2 border-indigo-500 px-4 pt-4 text-sm font-medium text-indigo-600" aria-current="page">{{ page_num }}</a> {% endif %} {% else %} <span class="inline-flex items-center border-t-2 border-transparent px-4 pt-4 text-sm font-medium text-gray-500">...</span> {% endif %} {% endfor %} </div> <div class="flex w-0 flex-1 justify-end"> {% if pagination.has_next %} <a href="{{ url_for('admin_orders', page=pagination.next_num) }}" class="inline-flex items-center border-t-2 border-transparent pl-1 pt-4 text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700"> Next <i class="fas fa-arrow-right ml-3 h-5 w-5 text-gray-400"></i> </a> {% endif %} </div> </nav> {% endif %}
{% else %} <p class="text-gray-600 text-center mt-10">No orders found.</p> {% endif %}
{% endblock %}
"""

# templates/admin_order_details.html (Updated Designer Link)
"""
{% extends "base.html" %}
{% block title %}Admin Order Details #{{ order.id }}{% endblock %}
{% block content %}
<div class="bg-white p-6 md:p-8 rounded-lg shadow-lg">
    <div class="flex justify-between items-start mb-6 border-b pb-4">
        <div> <h1 class="text-2xl font-bold text-gray-900">Order #{{ order.id }}</h1> <p class="text-sm text-gray-500 mt-1">Placed on: {{ order.order_date.strftime('%Y-%m-%d %H:%M:%S') }}</p> </div>
        <div> <span class="px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full {% if order.status == 'delivered' %} bg-green-100 text-green-800 {% elif order.status == 'cancelled' or order.status == 'failed_delivery' %} bg-red-100 text-red-800 {% elif order.status == 'out_for_delivery' %} bg-blue-100 text-blue-800 {% elif order.status == 'printing' or order.status == 'packaging' %} bg-yellow-100 text-yellow-800 {% else %} bg-gray-100 text-gray-800 {% endif %}"> {{ order.status.replace('_', ' ')|capitalize }} </span> </div>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div> <h2 class="text-xl font-semibold mb-3 text-gray-800">Customer Information</h2> <div class="space-y-3 text-sm"> <p><strong class="text-gray-600">Name:</strong> {{ order.customer_name }}</p> <p><strong class="text-gray-600">Phone:</strong> {{ order.customer_phone }}</p> <p><strong class="text-gray-600">Address:</strong><br>{{ order.customer_address|replace('\n', '<br>')|safe }}</p> {% if order.customer %} <p><strong class="text-gray-600">Registered User:</strong> <a href="{{ url_for('profile', username=order.customer.username) }}" class="text-indigo-600 hover:underline">{{ order.customer.username }} (#{{ order.user_id }})</a></p> {% else %} <p><strong class="text-gray-600">Registered User:</strong> Guest Order</p> {% endif %} </div> </div>
        <div> <h2 class="text-xl font-semibold mb-3 text-gray-800">Order Details</h2> <div class="space-y-3 text-sm"> <p><strong class="text-gray-600">Design:</strong> <a href="{{ url_for('design_detail', design_id=order.design_id) }}" class="text-indigo-600 hover:underline" target="_blank"> {{ order.design.title }} (#{{ order.design_id }}) </a> </p> <p><strong class="text-gray-600">Designer:</strong> <a href="{{ url_for('profile', username=order.design.designer.username) }}" class="text-indigo-600 hover:underline">{{ order.design.designer.username }}</a></p> <p><strong class="text-gray-600">Total Price:</strong> {{ "%.2f TND"|format(order.total_price) }}</p> <p><strong class="text-gray-600">Payment Method:</strong> Cash on Delivery</p> </div> <form action="{{ url_for('admin_update_order_status', order_id=order.id) }}" method="POST" class="mt-6 border-t pt-4"> <label for="status" class="block text-sm font-medium text-gray-700 mb-1">Update Order Status</label> <div class="flex items-center space-x-3"> <select id="status" name="status" class="flex-grow block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm rounded-md"> {% for status_option in statuses %} <option value="{{ status_option }}" {% if status_option == order.status %}selected{% endif %}> {{ status_option.replace('_', ' ')|capitalize }} </option> {% endfor %} </select> <button type="submit" class="px-4 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 transition duration-150 ease-in-out"> Update </button> </div> </form> </div>
    </div>
    <div class="mt-8 border-t pt-6"> <a href="{{ url_for('admin_orders') }}" class="text-indigo-600 hover:text-indigo-800 text-sm"> <i class="fas fa-arrow-left mr-1"></i> Back to All Orders </a> </div>
</div>
{% endblock %}
"""

# templates/profile.html (New Template)
"""
{% extends "base.html" %}
{% block title %}{{ user.username }}'s Profile{% endblock %}

{% block content %}
<div class="bg-white p-6 md:p-8 rounded-lg shadow-lg">
    <div class="flex items-center space-x-4 mb-6 border-b pb-4">
        {# Placeholder for avatar image later #}
        <div class="w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-500 text-2xl font-bold">
            {{ user.username[0]|upper }}
        </div>
        <div>
            <h1 class="text-2xl font-bold text-gray-900">{{ user.username }}</h1>
            <p class="text-sm text-gray-500">Joined: {{ user.join_date.strftime('%B %d, %Y') if user.join_date else 'N/A' }}</p>
            {% if user.is_designer %}
                <span class="inline-block bg-green-100 text-green-800 text-xs font-medium mt-1 px-2.5 py-0.5 rounded-full">Designer</span>
            {% endif %}
             {% if user.is_admin %}
                <span class="inline-block bg-purple-100 text-purple-800 text-xs font-medium mt-1 px-2.5 py-0.5 rounded-full">Admin</span>
            {% endif %}
        </div>
         {% if current_user.is_authenticated and current_user.id == user.id %}
            <div class="ml-auto"> {# Push edit button to the right #}
                <a href="#" class="text-sm text-indigo-600 hover:text-indigo-800 border border-indigo-300 hover:bg-indigo-50 rounded-md px-3 py-1.5">
                    <i class="fas fa-pencil-alt mr-1"></i> Edit Profile
                </a> {# Link to edit profile page (to be implemented) #}
            </div>
         {% endif %}
    </div>

    {% if user.bio %}
    <div class="mb-8">
        <h2 class="text-xl font-semibold mb-2 text-gray-800">About Me</h2>
        <p class="text-gray-700 whitespace-pre-wrap">{{ user.bio }}</p> {# whitespace-pre-wrap preserves line breaks #}
    </div>
    {% endif %}

    {% if user.is_designer %}
    <div class="mb-8">
        <h2 class="text-xl font-semibold mb-6 text-gray-800">Designs by {{ user.username }}</h2>
        {% if designs %}
        <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
            {% for design in designs %}
            {# Re-use design card structure from browse/index #}
            <div class="bg-white rounded-lg border border-gray-200 shadow-sm overflow-hidden hover:shadow-md transition-shadow duration-200 relative">
                <a href="{{ url_for('design_detail', design_id=design.id) }}">
                    <div class="aspect-square bg-gray-100 flex items-center justify-center">
                        {% if design.image_path %} <img src="{{ url_for('uploaded_file', filename=design.image_path) }}" alt="{{ design.title }} Preview" class="object-cover w-full h-full">
                        {% else %} <span class="text-gray-400 text-sm">No Preview</span> {% endif %}
                    </div>
                </a>
                <div class="p-4">
                    <a href="{{ url_for('design_detail', design_id=design.id) }}"> <h3 class="font-semibold text-lg mb-1 truncate">{{ design.title }}</h3> </a>
                    <div class="flex justify-between items-center mt-2">
                        <span class="font-bold text-indigo-600 text-sm">{{ "%.2f TND"|format(design.royalty_amount + 13.0) }}</span> {# Example Price #}
                        {% if current_user.is_authenticated %}
                            {% if current_user.is_favorite(design) %} <form action="{{ url_for('remove_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn active" title="Remove from Favorites"><i class="fas fa-heart"></i></button></form>
                            {% else %} <form action="{{ url_for('add_favorite', design_id=design.id) }}" method="POST" class="inline"><button type="submit" class="favorite-btn" title="Add to Favorites"><i class="far fa-heart"></i></button></form> {% endif %}
                        {% else %} <a href="{{ url_for('login', next=request.url) }}" class="favorite-btn" title="Login to Favorite"><i class="far fa-heart"></i></a> {% endif %}
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <p class="text-gray-600">This designer hasn't uploaded any approved designs yet.</p>
        {% endif %}
    </div>
    {% endif %}

    {# Add user's order history section here if needed #}

</div>
{% endblock %}
"""

# templates/cart.html (New Template)
"""
{% extends "base.html" %}
{% block title %}Shopping Cart{% endblock %}

{% block content %}
<h1 class="text-3xl font-semibold mb-8 text-gray-800">Your Shopping Cart</h1>

{% if cart_items %}
<div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
    {# Cart Items List #}
    <div class="lg:col-span-2 bg-white p-6 rounded-lg shadow">
        <h2 class="text-xl font-semibold mb-4 border-b pb-2">Items</h2>
        <div class="space-y-4">
            {% for item in cart_items %}
            <div class="flex items-center justify-between border-b pb-4">
                <div class="flex items-center space-x-4">
                    {# Image #}
                    <a href="{{ url_for('design_detail', design_id=item.design.id) }}">
                        {% if item.design.image_path %}
                            <img src="{{ url_for('uploaded_file', filename=item.design.image_path) }}" alt="{{ item.design.title }}" class="w-16 h-16 object-cover rounded-md border">
                        {% else %}
                            <div class="w-16 h-16 bg-gray-100 rounded-md flex items-center justify-center text-xs text-gray-400 border">No Img</div>
                        {% endif %}
                    </a>
                    {# Title & Designer #}
                    <div>
                        <a href="{{ url_for('design_detail', design_id=item.design.id) }}" class="font-medium text-gray-800 hover:text-indigo-600">{{ item.design.title }}</a>
                        <p class="text-sm text-gray-500">By <a href="{{ url_for('profile', username=item.design.designer.username) }}" class="hover:underline">{{ item.design.designer.username }}</a></p>
                    </div>
                </div>

                {# Quantity & Price & Remove #}
                <div class="flex items-center space-x-4">
                     {# Quantity Update Form #}
                    <form action="{{ url_for('update_cart_item', design_id=item.design.id) }}" method="POST" class="flex items-center">
                        <label for="quantity_{{ item.design.id }}" class="sr-only">Quantity</label>
                        <input type="number" id="quantity_{{ item.design.id }}" name="quantity" value="{{ item.quantity }}" min="1" max="10" {# Add max limit? #}
                               class="w-16 px-2 py-1 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 text-sm">
                        <button type="submit" class="ml-2 text-xs text-indigo-600 hover:underline" title="Update Quantity">Update</button>
                    </form>
                    {# Price #}
                    <div class="text-right w-24">
                        <p class="font-medium text-gray-800">{{ "%.2f TND"|format(item.total_item_price) }}</p>
                        <p class="text-xs text-gray-500">{{ "%.2f"|format(item.item_price) }} each</p>
                    </div>
                     {# Remove Button Form #}
                    <form action="{{ url_for('remove_from_cart', design_id=item.design.id) }}" method="POST">
                        <button type="submit" class="text-gray-400 hover:text-red-500" title="Remove Item">
                            <i class="fas fa-trash-alt"></i>
                        </button>
                    </form>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>

    {# Order Summary & Checkout #}
    <div class="lg:col-span-1">
        <div class="bg-white p-6 rounded-lg shadow sticky top-24"> {# Sticky summary #}
            <h2 class="text-xl font-semibold mb-4 border-b pb-2">Order Summary</h2>
            <div class="flex justify-between items-center mb-4">
                <span class="text-gray-600">Subtotal</span>
                <span class="font-medium text-gray-800">{{ "%.2f TND"|format(grand_total) }}</span>
            </div>
            <p class="text-sm text-gray-500 mb-4">Shipping & handling calculated at checkout (COD).</p>

            {# Checkout Form (COD Details) #}
            <form action="{{ url_for('checkout') }}" method="POST" class="border-t pt-4">
                 <h3 class="text-lg font-medium mb-3">Cash on Delivery Details</h3>
                 <div class="mb-3">
                    <label for="customer_name" class="block text-sm font-medium text-gray-700 mb-1">Full Name</label>
                    <input type="text" id="customer_name" name="customer_name" required class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500" value="{{ current_user.username if current_user.is_authenticated else '' }}">
                 </div>
                 <div class="mb-3">
                    <label for="customer_address" class="block text-sm font-medium text-gray-700 mb-1">Full Delivery Address</label>
                    <textarea id="customer_address" name="customer_address" rows="3" required class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"></textarea>
                 </div>
                 <div class="mb-4">
                    <label for="customer_phone" class="block text-sm font-medium text-gray-700 mb-1">Phone Number (for confirmation)</label>
                    <input type="tel" id="customer_phone" name="customer_phone" required class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500">
                 </div>
                 <button type="submit" class="w-full bg-green-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-green-700 transition duration-200 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 flex items-center justify-center">
                     <i class="fas fa-money-bill-wave mr-2"></i> Place Order (Pay on Delivery)
                 </button>
            </form>
        </div>
    </div>
</div>
{% else %}
<div class="text-center py-16 bg-white rounded-lg shadow">
    <i class="fas fa-shopping-cart text-6xl text-gray-300 mb-4"></i>
    <h2 class="text-2xl font-semibold text-gray-700 mb-2">Your Cart is Empty</h2>
    <p class="text-gray-500 mb-6">Looks like you haven't added any designs yet.</p>
    <a href="{{ url_for('browse') }}" class="bg-indigo-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-indigo-700 transition duration-200">
        Start Browsing
    </a>
</div>
{% endif %}

{% endblock %}
"""

# templates/order_history.html (New Template)
"""
{% extends "base.html" %}
{% block title %}My Order History{% endblock %}

{% block content %}
<h1 class="text-3xl font-semibold mb-8 text-gray-800">My Order History</h1>

{% if orders %}
<div class="bg-white shadow-md rounded-lg overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
            <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Order ID</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Placed</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Design</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Total Price (TND)</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                {# Add link to details later if needed #}
                {# <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th> #}
            </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
            {% for order in orders %}
            <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#{{ order.id }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ order.order_date.strftime('%Y-%m-%d %H:%M') }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 truncate max-w-xs" title="{{ order.design.title }}">
                     <a href="{{ url_for('design_detail', design_id=order.design_id) }}" class="hover:underline" target="_blank">
                        {{ order.design.title }}
                    </a>
                </td>
                 <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700 font-medium">{{ "%.2f"|format(order.total_price) }}</td>
                 <td class="px-6 py-4 whitespace-nowrap">
                     <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                        {% if order.status == 'delivered' %} bg-green-100 text-green-800
                        {% elif order.status == 'cancelled' or order.status == 'failed_delivery' %} bg-red-100 text-red-800
                        {% elif order.status == 'out_for_delivery' %} bg-blue-100 text-blue-800
                        {% elif order.status == 'printing' or order.status == 'packaging' %} bg-yellow-100 text-yellow-800
                        {% else %} bg-gray-100 text-gray-800 {% endif %}">
                        {{ order.status.replace('_', ' ')|capitalize }}
                     </span>
                 </td>
                 {# <td class="px-6 py-4 whitespace-nowrap text-sm font-medium"> <a href="#" class="text-indigo-600 hover:text-indigo-900">View Details</a> </td> #}
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% else %}
<div class="text-center py-16 bg-white rounded-lg shadow">
    <i class="fas fa-history text-6xl text-gray-300 mb-4"></i>
    <h2 class="text-2xl font-semibold text-gray-700 mb-2">No Orders Yet</h2>
    <p class="text-gray-500 mb-6">You haven't placed any orders with us.</p>
    <a href="{{ url_for('browse') }}" class="bg-indigo-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-indigo-700 transition duration-200">
        Browse Designs
    </a>
</div>
{% endif %}

{% endblock %}
"""


# --- Running the App (Instructions Updated) ---

# 1. Save code: Save this entire code block as `app.py`.
# 2. Create/Update 'templates' folder: Ensure you have a `templates` folder.
# 3. Save/Update HTML templates: Update `base.html`, `index.html`, `browse.html`, `design_detail.html`, `admin_users.html`, `admin_user_details.html`, `admin_design_details.html`, `admin_orders.html`, `admin_order_details.html`. Add the new `profile.html`, `cart.html`, `order_history.html`. Ensure all others are up-to-date.
# 4. Install dependencies (No new ones needed):
#    pip install Flask Flask-SQLAlchemy Flask-Migrate python-dotenv Werkzeug Flask-Login
# 5. Set Flask environment variables:
#    export FLASK_APP=app.py
#    export FLASK_ENV=development (or set FLASK_APP=app.py etc. for Windows)
# 6. Initialize/Upgrade the database (IMPORTANT due to User model changes):
#    flask db migrate -m "Add profile fields to User, cart, profile, order history features."
#    flask db upgrade
#    (Run these commands after saving the new app.py)
# 7. Create Admin User (If not already done).
# 8. Run the development server:
#    flask run
# 9. Test:
#    - Profiles: Click on usernames (designers) on browse/index/admin pages. View your own profile via nav link.
#    - Cart: Click "Add to Cart" on design details. View the cart via nav icon. Update quantities, remove items. Fill COD info and place order.
#    - Order History: After placing an order, check the "Order History" page via nav link.

# --- Main Execution ---
if __name__ == '__main__':
    app.run(debug=True)

