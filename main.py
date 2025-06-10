from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DecimalField, IntegerField, FileField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
from flask_mysqldb import MySQL
from decimal import Decimal
import os

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'secret_key'

mysql = MySQL(app)

UPLOAD_FOLDER = os.path.join('static', 'images')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

class RegisterForm(FlaskForm):
    name = StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    confirm_password = PasswordField("confirm_password",validators=[DataRequired()])
    address = StringField("Address", validators=[DataRequired()])
    contact= StringField("Contact", validators=[DataRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('customer', 'Customer')],
                       default='customer', validators=[DataRequired()],
                       render_kw={'disabled': True})
    submit = SubmitField("Register")


    def validate_email(self,field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

@app.route('/register.html', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        address = form.address.data
        contact = form.contact.data
        role = form.role.data
        plain_password = password

        if password != confirm_password:
            flash('Passwords do not match, please try again.', 'danger')
            #raise ValidationError('Email Already Taken')
            return redirect(url_for('register'))

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name,email,password,confirm_password,address,contact,role) VALUES (%s, %s, %s, %s, %s, %s, %s)",(name,email, plain_password,confirm_password,address,contact,role))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('login1'))

    return render_template('register.html', form = form)

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        mysql.connection.commit()
        cursor.close()
        if user and password == user[3]:
            session['user_id'] = user[0]
            if user[7] == 'admin':
                flash(f"Welcome, {user[2]}!", "success")
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('index'))

        else:
            flash("Login failed, Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

class LoginForm1(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    captcha = StringField('Captcha', validators=[DataRequired()])
    submit = SubmitField("Login")


@app.route('/login1.html', methods=['GET', 'POST'])
def login1():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        mysql.connection.commit()
        cursor.close()

        if user and password == user[3]:
            session['user_id'] = user[0]
            session['loggedin'] = True  # Set a session flag
            session['user_id'] = user[0]  # Store user ID in session
            session['email'] = user[2]  # Store user email
            if user[7] == 'customer':
                flash(f"Welcome, {user[2]}!", "success")
                return redirect(url_for('index'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Login failed, Please check your email and password")
            return redirect(url_for('login1'))

    return render_template('login1.html', form=form)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()

        # Delete user-related data
        cursor.execute("DELETE FROM cart WHERE id = %s", (user_id,))
        cursor.execute("DELETE FROM order_success WHERE id = %s", (user_id,))
        cursor.execute("DELETE FROM payment WHERE id = %s", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))

        mysql.connection.commit()
        cursor.close()

    session.clear()
    flash("Your account has been deleted successfully.", "success")
    return redirect(url_for('login1'))

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    new_confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message="Passwords must match")])

@app.route("/forget.html", methods=['GET', 'POST'])
def forget():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        old_password = form.old_password.data
        new_password = form.new_password.data
        new_confirm_password = form.new_confirm_password.data

        cursor = mysql.connection.cursor()

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if old_password == user[3]:
                cursor.execute("UPDATE users SET password = %s, confirm_password = %s WHERE email = %s", (new_password, new_confirm_password, email))
                mysql.connection.commit()

                flash("Password updated successfully!", "success")
                return redirect(url_for('forget'))
            else:
                flash("Old password is incorrect", "error")
        else:
            flash("Email not found", "error")
        cursor.close()

    return render_template('forget.html', form=form)

@app.route("/index.html")
def index():
    if "loggedin" in session:
        return render_template("index.html", email=session["email"])
    else:
        flash("Please log in first.", "warning")
    return render_template('index.html')

@app.route("/about.html")
def about():
    return render_template('about.html')

@app.route("/gallery.html")
def gallery():
    return render_template('gallery.html')

@app.route("/checkout.html", methods=["GET", "POST"])
def checkout():
    cursor = mysql.connection.cursor()

    # Check if user is logged in
    if "user_id" not in session:
        flash("Please log in to proceed to checkout.", "warning")
        return redirect(url_for("login1"))

    user_id = session["user_id"]

    # Fetch user details (including contact number)
    cursor.execute("SELECT name, email, address, contact FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("shop"))

    username, email, address, contact = user

    # Fetch cart items
    cursor.execute("SELECT cid, pname, qty, price, total FROM cart WHERE id = %s", (user_id,))
    cart_items = cursor.fetchall()

    if not cart_items:
        flash("Your cart is empty!", "warning")
        return redirect(url_for("shop"))

    if request.method == "POST" and "confirm_order" in request.form:
        try:
            for item in cart_items:
                cid, pname, qty, price, total = item
                cursor.execute("""
                    INSERT INTO order_success (id, name, email, address, contact, cid, pname, qty, price, total)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, username, email, address, contact, cid, pname, qty, price, total))

            mysql.connection.commit()

            # **Clear the cart after successful order placement**
            cursor.execute("DELETE FROM cart WHERE id = %s", (user_id,))
            mysql.connection.commit()

            flash("Order placed successfully!", "success")
            return redirect(url_for("bill"))  # Redirect to the bill page

        except Exception as e:
            mysql.connection.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("checkout"))

        finally:
            cursor.close()

    # Calculate subtotal and total quantity
    subtotal = sum(item[4] for item in cart_items)
    gst = subtotal * 18 / 100
    total = subtotal + gst

    # Render checkout page with contact number
    return render_template("checkout.html", username=username, email=email, address=address, contact=contact,
                           cart_items=cart_items, subtotal=subtotal, total=total)

@app.route('/bill.html')
def bill():
    if "user_id" not in session:
        flash("Please log in to view your bill.", "warning")
        return redirect(url_for("login1"))

    user_id = session["user_id"]
    cursor = mysql.connection.cursor()

    # 1️⃣ Delete the previous bill for this user
    cursor.execute("DELETE FROM payment WHERE id = %s", (user_id,))
    mysql.connection.commit()

    # 2️⃣ Fetch the latest order details for the logged-in user
    cursor.execute("""
        SELECT  name, email, address, contact, order_date
        FROM order_success 
        WHERE id = %s 
    """, (user_id,))
    order = cursor.fetchone()

    if not order:
        flash("No recent orders found.", "danger")
        return redirect(url_for("shop"))

    username, email, address, contact, order_date = order

    # 3️⃣ Fetch the order items
    cursor.execute("""
        SELECT pname, qty, price, total 
        FROM order_success 
        WHERE id = %s
    """, (user_id,))
    cart_items = cursor.fetchall()

    # 5️⃣ Insert new bill details into `payment` table

    if request.method == "POST" and "confirm_order" in request.form:
        try:
            for item in cart_items:
                pname, qty, price, total = item
                cursor.execute("""
                    INSERT INTO payment (id, name, email, address, contact, pname, qty, price, total)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, username, email, address, contact, pname, qty, price, total))

            mysql.connection.commit()

            # **Clear the cart after successful order placement**
            cursor.execute("DELETE FROM payment WHERE id = %s", (user_id,))
            mysql.connection.commit()

            flash("Bill Generated successfully!", "success")
            return redirect(url_for("index"))  # Redirect to the bill page

        except Exception as e:
            mysql.connection.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("checkout"))

        finally:
            cursor.close()

    subtotal = sum(float(item[3]) for item in cart_items)
    gst = subtotal * 18 / 100  # 18% GST
    grandtotal = subtotal + gst

    return render_template("bill.html",
                           username=username, email=email, address=address, contact=contact,
                           order_date=order_date,user_id=user_id, cart_items=cart_items,
                           subtotal=subtotal, total=grandtotal)


@app.route('/shop.html')
def shop():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    cursor.close()
    return render_template('shop.html', products=products)

@app.route("/dashboard.html")
def dashboard():
    return render_template('dashboard.html')

class ProductForm(FlaskForm):
    pname = StringField('Product Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    image = FileField('Image')
    submit = SubmitField('Add Product')

@app.route('/product.html')
def product():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    cursor.close()
    return render_template('product.html', products=products)

@app.route('/add_product.html', methods=['GET', 'POST'])
def add_product():
    form = ProductForm()

    if form.validate_on_submit():
        pname = form.pname.data
        price = form.price.data
        description = form.description.data
        stock = form.stock.data

        image = request.files.get('image')  # Using 'get' to prevent KeyError
        image_filename = None  # Initialize the variable
        filename = None  # Initialize filename to avoid unassigned variable warning

        if image:
            filename = image.filename
            image_filename = os.path.join(UPLOAD_FOLDER, filename)  # Save in 'static/uploads' folder
            image.save(image_filename)

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO product (pname, price, description, stock,image) VALUES (%s, %s, %s, %s, %s)",
                    (pname, price, description, stock,f"images/{filename}" if filename else None))  # Save relative path if filename exists
        mysql.connection.commit()

        cur.close()
        return redirect(url_for('product'))
    return render_template('add_product.html', form=form)

@app.route('/edit_product/<int:pid>', methods=['GET', 'POST'])
def edit_product(pid):
    form = ProductForm()

    # Retrieve the existing product details
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM product WHERE pid = %s", (pid,))
    product = cur.fetchone()
    cur.close()

    # If the product does not exist, redirect to the product list page or show an error
    if not product:
        flash('Product not found!', 'danger')
        return redirect(url_for('product'))

    # Prepopulate the form with the existing data
    if form.validate_on_submit():
        pname = form.pname.data
        price = form.price.data
        description = form.description.data
        stock = form.stock.data

        image = request.files.get('image')  # Get the new image if uploaded
        image_filename = None  # Initialize the variable
        filename = None  # Initialize filename to avoid unassigned variable warning

        if image:
            filename = image.filename
            image_filename = os.path.join(UPLOAD_FOLDER, filename)
            image.save(image_filename)
            image_path = f"images/{filename}"
        else:
            # If no new image is uploaded, keep the old one
            image_path = product[5]  # Assuming `image` column is at index 5

        # Update the product details in the database
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE product
            SET pname = %s, price = %s, description = %s, stock = %s, image = %s
            WHERE pid = %s
        """, (pname, price, description, stock, image_path, pid))
        mysql.connection.commit()
        cur.close()

        flash('Product updated successfully!', 'success')
        return redirect(url_for('product'))

    # Populate the form with existing data if it's a GET request
    form.pname.data = product[1]  # Adjust index based on your table structure
    form.price.data = product[2]
    form.description.data = product[3]
    form.stock.data = product[4]

    # Pass the product data (including image) to the template
    return render_template('edit_product.html', form=form, pid=pid, product=product)

@app.route('/delete_product/<int:pid>', methods=['GET'])
def delete_product(pid):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM product WHERE pid=%s", (pid,))
    mysql.connection.commit()
    cursor.close()
    flash("Product deleted successfully!", 'success')
    return redirect(url_for('product'))

@app.route('/add_to_cart/<int:pid>', methods=['POST'])
def add_to_cart(pid):
    if 'loggedin' not in session:
        flash("Please log in to add items to the cart.", "warning")
        return redirect(url_for('login1'))

    user_id = session['user_id']
    qty = int(request.form['qty'])

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM product WHERE pid=%s", (pid,))
    product = cursor.fetchone()

    if product:
        pname, price, image = product[1], product[2], product[5]
        price = Decimal(price)
        total_price = price * qty

        cursor.execute("SELECT * FROM cart WHERE id=%s AND pid=%s", (user_id, pid))
        existing_item = cursor.fetchone()

        if existing_item:
            new_qty = Decimal(existing_item[5]) + qty
            new_total_price = price * new_qty  #
            cursor.execute("UPDATE cart SET qty=%s, total=%s WHERE id=%s AND pid=%s",
                           (new_qty, new_total_price, user_id, pid))
        else:
            cursor.execute(
                "INSERT INTO cart (id, pname, price, qty, total, image, pid) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (user_id, pname, price, qty, total_price, image, pid))

        mysql.connection.commit()
        flash("Item added to cart!", "success")

    cursor.close()
    return redirect(url_for('cart'))

@app.route('/cart.html')
def cart():
    if 'user_id' not in session:
        flash("Please login to view the cart", "danger")
        return redirect(url_for('login1'))

    cursor = mysql.connection.cursor()
    user_id = session['user_id']
    cursor.execute("SELECT * FROM cart WHERE id=%s", (user_id,))
    cart_items = cursor.fetchall()
    cursor.close()

    total_price = sum(item[4] * item[5] for item in cart_items)
    subtotal = sum(item[4] * item[5] for item in cart_items)
    gst = subtotal * 18 / 100
    total = subtotal + gst

    session['subtotal'] = subtotal
    session['total'] = total

    return render_template("cart.html", cart_items=cart_items, total_price=total_price, subtotal=subtotal,total=total)


@app.route('/remove_from_cart/<int:cid>')
def remove_from_cart(cid):
    cursor = mysql.connection.cursor()

    # Check if the item is already in order_success
    cursor.execute("SELECT * FROM order_success WHERE cid=%s", (cid,))
    if cursor.fetchone():
        flash("Cannot remove item from cart. It has already been ordered.", "danger")
        return redirect(url_for('cart'))

    # Now delete the cart item
    cursor.execute("DELETE FROM cart WHERE cid=%s", (cid,))
    mysql.connection.commit()
    cursor.close()

    flash("Item removed from cart!", "success")
    return redirect(url_for('cart'))

@app.route("/manage_order.html")
def manage_order():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT oid, id, name, email, address, contact, cid, pname, qty, price, total, order_date FROM order_success")
    orders = cursor.fetchall()
    cursor.close()

    return render_template('manage_order.html', orders=orders)

@app.route("/users.html")
def users():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, name, email, address, contact, role, address FROM users")
    users = cursor.fetchall()
    cursor.close()

    return render_template('users.html',users=users)

class FeedbackForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    contact = StringField("Contact", validators=[DataRequired()])
    message = StringField("Message", validators=[DataRequired()])
    submit = SubmitField("send Feedback")

@app.route("/feedback.html", methods=['GET', 'POST'])
def feedback():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login1"))

    form = FeedbackForm()
    user_id = session["user_id"]

    # Fetch the user's details
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, name, email, contact FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("index"))
    cursor.close()

    if user:
        user_id, username, email, contact = user
    else:
        user_id, username, email, contact = None, "", "", ""

    if form.validate_on_submit():
        message = form.message.data

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO feedback (id, username, email, contact, message) VALUES (%s, %s, %s, %s, %s)",
                       (user_id, username, email, contact, message))  # Include 'id' in the INSERT statement
        mysql.connection.commit()
        cursor.close()

        flash("Thank you for your feedback!", "success")
        return redirect(url_for("index"))

    return render_template("feedback.html", form=form, username=username, email=email, contact=contact)

@app.route("/feedbackshow.html", methods=['GET', 'POST'])
def feedbackshow():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, contact, message FROM feedback")
    feedback_data = cursor.fetchall()  # Get all feedback entries
    cursor.close()
    return render_template('feedbackshow.html', feedback_data=feedback_data)

@app.route("/stock.html")
def stock():
    cursor = mysql.connection.cursor()

    # Fetch total stock from product table (ensure stock is converted to INT)
    cursor.execute("SELECT pid, pname, stock FROM product")
    products = cursor.fetchall()

    stock_data = []

    for product in products:
        pid, pname, total_stock = product
        total_stock = int(total_stock)  # Convert stock to integer

        # Fetch ordered quantity from order_success table
        cursor.execute("SELECT COALESCE(SUM(qty), 0) FROM order_success WHERE pname = %s", (pname,))
        ordered_qty = cursor.fetchone()[0]

        # Ensure ordered_qty is converted to an integer
        ordered_qty = int(ordered_qty)

        # Calculate remaining stock
        remaining_stock = total_stock - ordered_qty

        stock_data.append({
            "pname": pname,
            "total_stock": total_stock,
            "ordered_qty": ordered_qty,
            "remaining_stock": remaining_stock
        })

    cursor.close()
    return render_template("stock.html", stock_data=stock_data)

@app.route("/profile.html")
def profile():
    return render_template('profile.html')

app.run(debug=True)