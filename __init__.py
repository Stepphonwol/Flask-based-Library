import os

from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flaskr.db import get_db
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, IntegerField
from passlib.hash import sha256_crypt
from functools import wraps


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    @app.route('/')
    def hello():
        return render_template('home.html')


    class RegisterForm(Form):
        reader_name = StringField('reader_name', [validators.Length(min=1, max=50)])
        gender = StringField('gender', [validators.Length(min=1, max=50)])
        department = StringField('department', [validators.Length(min=1, max=50)])
        user_grade = IntegerField('user_grade', [validators.NumberRange(min=1, max=5000)])
        password = PasswordField('Password', [
            validators.DataRequired(),
            validators.EqualTo('confirm', message="Password do not match!!")
        ])
        confirm = PasswordField('Confirm Password')


    class BookForm(Form):
        ISBN = IntegerField('ISBN', [validators.NumberRange(min=1, max=50)])
        book_name = StringField('book_name', [validators.Length(min=1, max=50)])
        press = StringField('press', [validators.Length(min=1, max=50)])
        publicating_date = StringField('publicating_date', [validators.Length(min=1, max=50)])
        author = StringField('author', [validators.Length(min=1, max=50)])
        abstract = StringField('abstract', [validators.Length(min=1, max=50)])
        num = IntegerField('num', [validators.NumberRange(min=1, max=50)])


    # Registering
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm(request.form)
        if request.method == 'POST' and form.validate():
            reader_name = form.reader_name.data
            gender = form.gender.data
            department = form.department.data
            user_grade = form.user_grade.data
            password = sha256_crypt.encrypt(str(form.password.data))
            #app.logger.info(password)

            db = get_db()
            error = None

            if (reader_name or password) is None:
                error = 'Invalid!!!'

            if error is None:
                db.execute(
                    'INSERT INTO reader (reader_name, gender, department, user_grade, password) VALUES(?, ?, ?, ?, ?)',
                    (reader_name, gender, department, user_grade, password)
                )
                db.commit()
                flash("Successfully registered!!", 'success')
                return redirect(url_for('login'))
            else:
                flash(error, 'failure')
                return redirect(url_for('register'))
        return render_template('register.html', form=form)


    # Logging
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            reader_name = request.form['reader_name']
            password_candidate = request.form['password']
            app.logger.info(password_candidate)

            db = get_db()

            readers = db.execute(
                'SELECT * FROM reader WHERE reader_name = ?', (reader_name,)
            ).fetchall()

            if readers is not None:
                sign = False
                for reader in readers:
                    password = reader['password']
                    #app.logger.info(password)
                    if sha256_crypt.verify(password_candidate, password):
                        session['logged_in'] = True
                        session['reader_name'] = reader_name
                        session['reader_id'] = reader['reader_id']
                        sign = True
                        break
                if sign == False:
                    error = 'Invalid login!!'
                    return render_template('login.html', error=error)
                flash("You are now logged in", 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Reader not found'
                return render_template('login.html', error=error)

        return render_template('login.html')


    # Logging judgement
    def is_logged_in(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if 'logged_in' in session:
                return f(*args, **kwargs)
            else:
                flash('Unauthorized, please login!!', 'danger')
                return redirect(url_for('login'))
        return wrap


    # Log out
    @app.route('/logout')
    def logout():
        session.clear()
        flash('You are now logged out', 'success')
        return redirect(url_for('login'))


    # Main page for the reader; borrowing information for each reader
    @app.route('/dashboard')
    @is_logged_in
    def dashboard():
        db = get_db()
        reader = db.execute(
            'SELECT * FROM reader WHERE reader_id = ?', (session['reader_id'],)
        ).fetchone()
        return render_template('dashboard.html', reader=reader)


    # Show information of all readers
    @app.route('/reader')
    def reader():
        db = get_db()

        readers = db.execute(
            'SELECT * FROM reader'
        ).fetchall()

        if readers is not None:
            return render_template('reader.html', readers=readers)
        else:
            msg = 'No readers found'
            return render_template('reader.html', msg=msg)


    # Editing a reader
    @app.route('/edit_reader/<string:reader_id>', methods=['GET', 'POST'])
    def edit_reader(reader_id):
        db = get_db()
        reader = db.execute(
            'SELECT * FROM reader WHERE reader_id = ?', (reader_id,)
        ).fetchone()

        form = RegisterForm(request.form)

        form.reader_name.data = reader['reader_name']
        form.gender.data = reader['gender']
        form.department.data = reader['department']
        form.user_grade.data = reader['user_grade']

        if request.method == 'POST' and form.validate():
            reader_name = request.form['reader_name']
            gender = request.form['gender']
            department = request.form['department']
            user_grade = request.form['user_grade']
            password = request.form['password']

            error = None

            if (reader_name or password) is None:
                error = "Invalid!!!"

            if error is None:
                db.execute(
                    'UPDATE reader SET reader_name = ?, gender = ?, department = ?, password = ?, user_grade = ? WHERE reader_id = ?',
                    (reader_name, gender, department, password, user_grade, reader_id, )
                )
                db.commit()
                flash("Reader successfully edited!", 'success')
                return redirect(url_for('dashboard'))
            else:
                flash(error, 'danger')
                #return redirect(url_for('/edit_book/book_id'))
        return render_template('edit_reader.html', form=form)

    # Show information of all books
    @app.route('/books')
    def book():
        db = get_db()

        books = db.execute(
            'SELECT * FROM book'
        ).fetchall()

        if books is not None:
            return render_template('book.html', books=books)
        else:
            msg = 'No books found'
            return render_template('book.html', msg=msg)


    # Adding a book
    @app.route('/add_book', methods=['GET', 'POST'])
    def add_book():
        form = BookForm(request.form)
        if request.method == 'POST' and form.validate():
            ISBN = form.ISBN.data
            book_name = form.book_name.data
            press = form.press.data
            publicating_date = form.publicating_date.data
            author = form.author.data
            abstract = form.abstract.data
            num = int(form.num.data)

            db = get_db()
            error = None

            if db.execute(
                'SELECT ISBN from book WHERE ISBN = ?', (ISBN,)
            ).fetchone() is not None:
                error = "Repeated book!"

            if (ISBN or book_name) is None:
                error = "Invalid!!!"

            if error is None:
                db.execute(
                    'INSERT INTO book (ISBN, book_name, press, publicating_date, author, abstract, num) VALUES(?, ?, ?, ?, ?, ?, ?)',
                    (ISBN, book_name, press, publicating_date, author, abstract, num)
                )
                db.commit()
                flash("Book successfully added!", 'success')
                return redirect(url_for('add_book'))
            else:
                flash(error, 'danger')
                return redirect(url_for('add_book'))
        return render_template('add_book.html', form=form)


    # Editing a book
    @app.route('/edit_book/<string:book_id>', methods=['GET', 'POST'])
    @is_logged_in
    def edit_book(book_id):
        db = get_db()
        book = db.execute(
            'SELECT * FROM book WHERE book_id = ?', (book_id)
        ).fetchone()

        form = BookForm(request.form)

        form.ISBN.data = book['ISBN']
        form.book_name.data = book['book_name']
        form.press.data = book['press']
        form.publicating_date.data = book['publicating_date']
        form.author.data = book['author']
        form.abstract.data = book['abstract']
        form.num.data = book['num']

        if request.method == 'POST' and form.validate():
            ISBN = request.form['ISBN']
            book_name = request.form['book_name']
            press = request.form['press']
            publicating_date = request.form['publicating_date']
            author = request.form['author']
            abstract = request.form['abstract']
            num = request.form['num']

            error = None

            #if db.execute(
                #'SELECT * FROM book WHERE ISBN = ?', (ISBN,)
            #).fetchone() is not None:
                #error = "Invalid!!!Repeated ISBN!!!"

            if (ISBN or book_name) is None:
                error = "Invalid!!!"

            if error is None:
                db.execute(
                    'UPDATE book SET ISBN = ?, book_name = ?, press = ?, publicating_date = ?, author = ?, abstract = ?, num = ? WHERE book_id = ?',
                    (ISBN, book_name, press, publicating_date, author, abstract, num, book_id)
                )
                db.commit()
                flash("Book successfully edited!", 'success')
                return redirect(url_for('book'))
            else:
                flash(error, 'danger')
                #return redirect(url_for('/edit_book/book_id'))
        return render_template('edit_book.html', form=form)


    # Deleting a reader
    @app.route('/delete_reader/<string:reader_id>', methods=['POST'])
    @is_logged_in
    def delete_reader(reader_id):
        db = get_db()
        db.execute(
            'DELETE FROM reader WHERE reader_id = ?', (reader_id,)
        )
        db.commit()

        flash("Reader deleted!", 'success')

        return redirect(url_for('dashboard'))


    # Deleting a book
    @app.route('/delete_book/<string:book_id>', methods=['POST'])
    @is_logged_in
    def delete_book(book_id):
        db = get_db()
        db.execute(
            'DELETE FROM book WHERE book_id = ?', (book_id,)
        )
        db.commit()

        flash("Book deleted!", 'success')

        return redirect(url_for('book'))


    from . import db
    db.init_app(app)

    return app