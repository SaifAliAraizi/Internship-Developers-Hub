# import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    transactions_db = db.execute(
        "SELECT symbol, SUM(shares) as shares, price FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]

    return render_template("index.html", database=transactions_db, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Get inputs
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate inputs
        if not symbol:
            return apology("missing symbol")
        stock = lookup(symbol)
        if stock is None:
            return apology("invalid symbol")
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("invalid shares")

        shares = int(shares)
        user_id = session["user_id"]

        # Lookup stock price
        price = stock["price"]
        total_cost = shares * price

        # Check user's cash
        rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash = rows[0]["cash"]

        if cash < total_cost:
            return apology("can't afford")

        # Record the transaction
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            user_id,
            stock["symbol"],
            shares,
            price
        )

        # Update user's cash
        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ?",
            total_cost,
            user_id
        )

        # Confirm purchase
        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get(
                "username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
                rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbolFromUser = request.form.get("symbol")
        lookedUp = lookup(symbolFromUser)

        # Check if stock exist
        if lookedUp is None:
            return apology("stock symbol does not exist")
        else:
            stock = lookedUp["name"]
            price = usd(lookedUp["price"])
            symbol = lookedUp["symbol"]
            return render_template("quoted.html", name=stock, price=price, symbol=symbol)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Must Give Username")

        if not password:
            return apology("Must Give Password")

        if not confirmation:
            return apology("Must Give Confirmation")

        if password != confirmation:
            return apology("Password Do Not Match")

        hashPass = generate_password_hash(password)

        try:
            new_user = db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", username, hashPass)
        except:
            return apology("Username already exists")
        session["user_id"] = new_user

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == "POST":
        # Get inputs
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate inputs
        if not symbol:
            return apology("missing symbol")

        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("invalid shares")

        shares = int(shares)

        # Check ownership of the stock
        rows = db.execute(
            "SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id = ? AND symbol = ?",
            user_id,
            symbol,
        )

        if not rows or rows[0]["total_shares"] is None or rows[0]["total_shares"] <= 0:
            return apology("you don't own this stock")

        owned_shares = rows[0]["total_shares"]
        if shares > owned_shares:
            return apology("too many shares")

        # Lookup stock price
        stock = lookup(symbol)
        if stock is None:
            return apology("invalid symbol")

        price = stock["price"]
        proceeds = shares * price

        # Record the sale
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            user_id,
            symbol,
            -shares,  # Negative to indicate sale
            price,
        )

        # Update user's cash
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            proceeds,
            user_id,
        )

        # Confirm sale
        flash("Sold!")
        return redirect("/")

    else:
        # Get list of symbols owned by the user for the select menu
        symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
            user_id,
        )

        return render_template("sell.html", symbols=symbols)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    # Query the transactions table, order by date
    transactions = db.execute(
        """
        SELECT symbol, shares, price, date
        FROM transactions
        WHERE user_id = ?
        ORDER BY date DESC
        """,
        user_id,
    )

    if not transactions:
        flash("No transactions found", "warning")

    # Pass transactions to the template
    return render_template("history.html", transactions=transactions)


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """Allow users to add cash to their account."""
    if request.method == "POST":
        # Get input from user
        cash_to_add = request.form.get("cash")

        # Validate input
        if not cash_to_add or not cash_to_add.isdigit() or int(cash_to_add) <= 0:
            return apology("Invalid cash amount")

        cash_to_add = int(cash_to_add)

        # Update user's cash
        user_id = session["user_id"]
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",
                   cash_to_add, user_id)

        # Flash success message and redirect to home
        flash(f"Successfully added ${cash_to_add}!")
        return redirect("/")
    else:
        return render_template("add_cash.html")


if __name__ == "__main__":
    app.run(debug=True)