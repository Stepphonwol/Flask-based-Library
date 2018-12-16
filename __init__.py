import os

from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flaskr.db import get_db
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, IntegerField
from passlib.hash import sha256_crypt
from functools import wraps
from datetime import datetime, timedelta


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
        books = db.execute(
            'SELECT book_id, borrow_date, return_date FROM reader NATURAL LEFT JOIN borrow WHERE reader_id = ? AND returned = ?',
            (session['reader_id'], 0)
        )
        return render_template('dashboard.html', reader=reader, books=books)


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
        error = None

        records = db.execute(
            'SELECT * FROM borrow WHERE reader_id = ?', (reader_id,)
        ).fetchall()

        # Check if this reader has some book that he hasn't returned
        if records is not None:
            for record in records:
                if record['returned'] == 0:
                    error = "You haven't returned %s" % record['book_id']

        if error is None:
            db.execute(
                'DELETE FROM reader WHERE reader_id = ?', (reader_id,)
            )
            db.commit()

            flash("Reader deleted!", 'success')
        else:
            flash(error, 'danger')
            return redirect(url_for('book'))

        return redirect(url_for('hello'))


    # Deleting a book
    @app.route('/delete_book/<string:book_id>', methods=['POST'])
    @is_logged_in
    def delete_book(book_id):
        db = get_db()
        error = None

        borrowed = db.execute(
            'SELECT * FROM borrow WHERE book_id = ?', (book_id,)
        ).fetchall()

        # Check whether this book has been borrowed
        for borrow in borrowed:
            if borrow['returned'] == 0:
                error = "%s has borrowed this book!!!" % borrow['reader_id']

        if error is None:
            db.execute(
                'DELETE FROM book WHERE book_id = ?', (book_id,)
            )
            db.commit()

            flash("Book deleted!", 'success')
        else:
            flash(error, 'danger')
        return redirect(url_for('book'))


    # Search books
    @app.route('/search_book', methods=['GET', 'POST'])
    @is_logged_in
    def search_book():
        if request.method == 'POST':
            book_id = request.form['book_id']
            ISBN = request.form['ISBN']
            book_name = request.form['book_name']
            press = request.form['press']
            publicating_date = request.form['publicating_date']
            author = request.form['author']
            abstract = request.form['abstract']
            num = request.form['num']

            db = get_db()
            error = None

            if (book_id and ISBN and book_name and press and publicating_date and author and abstract and num) is None:
                error = "All empty!!!No!!!"

            sentence = "SELECT * FROM book WHERE"
            if error is None:
                if book_id:
                    sentence += " book_id = '%s'" % book_id + " AND"
                if ISBN:
                    sentence += " ISBN = '%s'" % ISBN + " AND"
                if book_name:
                    sentence += " book_name = '%s'" % book_name + " AND"
                if press:
                    sentence += " press = '%s'" % press + " AND"
                if publicating_date:
                    sentence += " publicating_date = '%s'" % publicating_date + " AND"
                if author:
                    sentence += " author = '%s'" % author + " AND"
                if abstract:
                    sentence += " abstract = '%s'" % abstract + " AND"
                if num:
                    sentence += " num = '%s'" % num
                app.logger.info(sentence)
                app.logger.info(sentence[:-4])
                books = db.execute(
                    sentence[:-4]
                ).fetchall()
                return render_template('book.html', books=books)
            else:
                msg = "bug"
                return render_template("book.html", msg=msg)
        return render_template("search_book.html")


    # Search readers
    @app.route('/search_reader', methods=['GET', 'POST'])
    @is_logged_in
    def search_reader():
        if request.method == 'POST':
            reader_id = request.form['reader_id']
            reader_name = request.form['reader_name']
            gender = request.form['gender']
            department = request.form['department']
            user_grade = request.form['user_grade']

            db = get_db()
            error = None

            if (reader_id and reader_name and gender and department and user_grade) is None:
                error = "All empty!!!No!!!"

            sentence = "SELECT * FROM reader WHERE"
            if error is None:
                if reader_id:
                    sentence += " reader_id = '%s'" % reader_id + " AND"
                if reader_name:
                    sentence += " reader_name = '%s'" % reader_name + " AND"
                if gender:
                    sentence += " gender = '%s'" % gender + " AND"
                if department:
                    sentence += " department = '%s'" % department + " AND"
                if user_grade:
                    sentence += " publicating_date = '%s'" % user_grade + " AND"
                app.logger.info(sentence)
                app.logger.info(sentence[:-4])
                readers = db.execute(
                    sentence[:-4]
                ).fetchall()
                return render_template('reader.html', readers=readers)
            else:
                msg = "bug"
                return render_template("reader.html", msg=msg)
        return render_template("search_reader.html")


    # Borrow
    @app.route('/borrow_book/<string:book_id>', methods=['GET', 'POST'])
    @is_logged_in
    def borrow_book(book_id):
        db = get_db()
        error = None
        book = db.execute(
            'SELECT * FROM book WHERE book_id = ?', (book_id,)
        ).fetchone()
        cur_num = book['num']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if cur_num <= 0:
            error = "This book is not available!!!"

        records = db.execute(
            'SELECT * FROM borrow WHERE reader_id = ? AND book_id = ?', (session['reader_id'], book_id)
        ).fetchall()

        # To see if this book is borrowed by this reader
        for record in records:
            if record['returned'] == 0:
                error = "You have borrowed this book!!!"

        # Check if this reader failed to return some book on due date
        borrowed_books = db.execute(
            'SELECT * FROM reader NATURAL LEFT JOIN borrow WHERE reader_id = ?', (session['reader_id'],)
        ).fetchall()

        for book in borrowed_books:
            if book['returned'] == 0 and now > book['return_date']:
                error = "You haven't returned %s on due date!!!" % book['book_id']

        if error is None:
            app.logger.info(cur_num)
            db.execute(
                'UPDATE book SET num = ? WHERE book_id = ?', (cur_num - 1, book_id)
            )
            # Acquire time
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            end = (datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
            db.execute(
                'INSERT INTO borrow (borrow_date, book_id, reader_id, return_date, returned) VALUES(?, ?, ?, ?, ?)', (now, book_id, session['reader_id'], end, 0)
            )
            db.commit()
            flash("Successfully borrowed!!!", 'success')
        else:
            flash(error, 'danger')
        return redirect(url_for('book'))


    # Return
    @app.route('/return_book/<string:book_id>', methods=['GET', 'POST'])
    @is_logged_in
    def return_book(book_id):
        db = get_db()
        error = None
        exact_id = 0
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        records = db.execute(
            'SELECT * FROM borrow WHERE book_id = ? AND reader_id = ?', (book_id, session['reader_id'])
        ).fetchall()

        # Check if this reader has borrowed this book
        if records is None:
            error = "You didn't borrow this book at all!!!"
        else:
            sign = 0
            for record in records:
                if record['returned'] == 0:
                    exact_id = record['record_id']
                    break
                else:
                    sign = sign + 1
            if sign == len(records):
                error = "You didn't borrow this book!!!"

        # Check if this book would be returned on due date
        for record in records:
            if record['returned'] == 0 and now > record['return_date']:
                msg = "You should return this book on %s but it's %s now!!!" % (record['return_date'], now)
                flash(msg, 'danger')

        if error is None:
            db.execute(
                'UPDATE book SET num = num + 1 WHERE book_id = ?', (book_id,)
            )
            db.execute(
                'UPDATE borrow SET returned = ? WHERE record_id = ?', (1, exact_id)
            )
            db.commit()
            flash("You have returned this book successfully!!!", 'success')
        else:
            flash(error, 'danger')
        return redirect(url_for('book'))


    # Search Unfaithful Readers
    @app.route('/search_unfaith')
    def search_unfaith():
        db = get_db()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        unfaithful_readers = db.execute(
            'SELECT reader_id, reader_name, gender, department, user_grade FROM reader NATURAL LEFT JOIN borrow WHERE returned = 0 AND return_date < ?', (now,)
        ).fetchall()
        return render_template('reader.html', readers=unfaithful_readers)


    from . import db
    db.init_app(app)

    return app