import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    # Show username
    username = db.execute(
        "SELECT username FROM users WHERE id = ?;", session["user_id"])

    # Show stocks
    symbols = db.execute(
        "SELECT DISTINCT symbol FROM purchases WHERE owner_id = ?;", session["user_id"])

    stock_names = []
    for i in range(len(symbols)):
        stock_symbol = symbols[i]['symbol']
        stock = lookup(stock_symbol)
        stock_names.append(stock['name'])

    # Show number of shares
    shares = []
    for i in range(len(symbols)):
        share = db.execute("SELECT COUNT (*) FROM purchases WHERE owner_id = ? AND symbol LIKE ?;",
                           session["user_id"], symbols[i]['symbol'])
        shares.append(share[0]['COUNT (*)'])

    # Show current price of each share
    stock_prices = []
    for i in range(len(symbols)):
        stock_symbol = symbols[i]['symbol']
        stock = lookup(stock_symbol)
        stock_prices.append(stock['price'])

    # Show cash
    cash = db.execute("SELECT cash FROM users WHERE id = ?;",
                      session["user_id"])

    stocks_value = 0
    for i in range(len(symbols)):
        stocks_value += shares[i] * stock_prices[i]

    total = int(cash[0]['cash']) + stocks_value

    # Iterator for jinja template
    length = len(symbols)

    return render_template("index.html", username=username[0]['username'],
                           length=length,
                           stock_names=stock_names,
                           shares=shares,
                           stock_prices=stock_prices,
                           cash=usd(cash[0]['cash']),
                           total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Ensure user typed stock symbol and that stock exists
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 403)

        symbol = request.form.get("symbol")
        if not lookup(symbol):
            return apology("stock not found", 403)

        # Ensure user typed valid number of shares
        if not request.form.get("shares"):
            return apology("must provide number of shares", 403)

        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except (KeyError, TypeError, ValueError):
            return apology("shares field must be a positive integer", 403)

        if shares <= 0:
            return apology(f"you can't buy {shares} amount of shares", 403)

        # Check out stock current price
        stock = lookup(symbol)
        price = stock['price']

        # Check out how much money user have
        money = db.execute(
            "SELECT cash FROM users WHERE id = ?;", session["user_id"])
        cash = money[0]['cash']

        # Return apology if user don't have enough money
        if price * shares > cash:
            return apology("not enough cash", 403)

        # Buy
        cash = cash - (price * shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?;",
                   cash, session["user_id"])

        for _ in range(shares):
            db.execute("INSERT INTO purchases (owner_id, symbol, price) VALUES (?, ?, ?);",
                       session["user_id"], stock["symbol"], price)
            db.execute("INSERT INTO history (user_id, stock_symbol, operation) VALUES (?, ?, ?);",
                       session["user_id"], stock["symbol"], "bought")

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    username = db.execute(
        "SELECT username FROM users WHERE id = ?;", session["user_id"])
    username = username[0]['username']

    rows = db.execute(
        "SELECT * FROM history WHERE user_id = ? ORDER BY timestamp;", session["user_id"])

    return render_template("history.html", username=username, rows=rows)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
        # Ensure is not blank
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        # Ensure symbol exists
        symbol = request.form.get("symbol")
        if not lookup(symbol):
            return apology("symbol not found", 403)

        # Show stock info
        stock = lookup(symbol)
        # stock.price = usd(stock.price)
        return render_template("quoted.html", stock=stock)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password was confirmed
        elif not request.form.get("confirmation") or request.form.get("confirmation") != request.form.get("password"):
            return apology("must confirm password", 403)

        # Check if username is taken
        taken = db.execute(
            "SELECT * FROM users WHERE username = ?;", request.form.get("username"))
        if len(taken) != 0:
            return apology("username already taken", 403),

        # Get hash from password
        hash = generate_password_hash(request.form.get("password"))

        # Add user to database
        username = request.form.get("username")
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?);", username, hash)

        # Log user in
        id = db.execute("SELECT id FROM users WHERE username = ?;", username)
        session["user_id"] = id[0]['id']

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Ensure user provided symbol
        if not request.form.get("symbol"):
            return apology("must provide stock you want to sell", 403)

        # Ensure valid number of shares
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except (KeyError, TypeError, ValueError):
            return apology("shares field must be a positive integer", 403)

        if shares <= 0:
            return apology(f"you can't sell {shares} amount of shares", 403)

        # shares can't be higher than num of shares users owns
        owned = db.execute("SELECT COUNT (*) FROM purchases WHERE owner_id = ? AND symbol LIKE ?;",
                           session["user_id"], request.form.get("symbol"))
        owned = owned[0]["COUNT (*)"]

        if shares > owned:
            return apology(f"you only have {owned} shares to sell")

        # Sell
        # Look up stocks current price
        symbol = request.form.get("symbol")
        stock = lookup(symbol)
        price = stock["price"]

        # Add to user cash
        money = db.execute(
            "SELECT cash FROM users WHERE id = ?;", session["user_id"])
        cash = money[0]['cash']

        cash += price * shares

        # Update data base: add cash and remove purchases
        db.execute("UPDATE users SET cash = ? WHERE id = ?;",
                   cash, session["user_id"])

        for i in range(shares):
            db.execute("DELETE FROM purchases WHERE id IN (SELECT id FROM purchases WHERE symbol = ? AND owner_id = ? LIMIT 1);",
                       symbol, session["user_id"])
            db.execute("INSERT INTO history (user_id, stock_symbol, operation) VALUES (?, ?, ?);",
                       session["user_id"], symbol, "selled")

        return redirect("/")

    else:
        symbols = db.execute(
            "SELECT DISTINCT symbol FROM purchases WHERE owner_id = ?;", session["user_id"])
        stocks = []
        for i in range(len(symbols)):
            stocks.append(symbols[i]['symbol'])

        return render_template("sell.html", stocks=stocks)
