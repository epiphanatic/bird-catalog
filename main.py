from flask import Flask, render_template, request, redirect, url_for,\
    jsonify, flash, session as login_session
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask_jsglue import JSGlue

jsglue = JSGlue()

app = Flask(__name__)
jsglue.init_app(app)
app.secret_key = "super secret key"

# *****  BEGIN OAUTH STUFF **********
#
# ***********************************


# client secrets json file for google oauth
# TODO: uncomment
CLIENT_ID = json.loads(
    open('./client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog1.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


# Connect to google oauth
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '  # noqa
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/clearSession')
def clearSession():
    login_session.clear()
    return "Session cleared"


# disconnect from google
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['credentials']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    # headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    result = h.request(url, "GET")[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Facebook login stuff


# connect to fb

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/v2.9/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (  # noqa
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    # Extract the access token from response
    token = 'access_token=' + data['access_token']

    url = 'https://graph.facebook.com/v2.9/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.9/me/picture?%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '  # noqa

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % \
          (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['facebook_id']
    return "you have been logged out"


# disconnect from Google or FB - call on logout from template

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()

        if login_session['provider'] == 'facebook':
            fbdisconnect()

        del login_session['provider']

        flash("You have successfully been logged out.")
        return redirect(url_for('main'))
    else:
        flash("You were not logged in to begin with!")
        return redirect(url_for('main'))

# *****  END OAUTH STUFF **********
#
# ***********************************


# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DB Helper Functions

def getCategories():
    categories = session.query(Category).order_by(Category.name).all()
    return categories


# endpoints for APIs to view Category information

# shows all categories
@app.route('/category/JSON')
def category_json():
    categories = session.query(Category).all()
    return jsonify(Category=[c.serialize for c in categories])


# shows all items for passed category id
@app.route('/category/<int:category_id>/JSON')
def items_json(category_id):
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Item=[i.serialize for i in items])


# shows item for passed item id
@app.route('/item/<int:item_id>/JSON')
def item_json(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


# App endpoints

@app.route("/")
def main():
    categories = getCategories()
    items = session.query(Item).order_by(desc(Item.date_created)).all()
    # the following adds the category name to each item object for display
    #   under latest items
    for item in items:
        category = session.query(Category).filter_by(id=item.category_id).one()
        category_name = category.name
        setattr(item, 'category_name', category_name)
    return render_template("latest_items.html",
                           categories=categories,
                           items=items)


@app.route("/show_items/<int:category_id>")
def show_items(category_id):
    categories = getCategories()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    count = len(items)
    return render_template("items.html",
                           items=items,
                           category=category,
                           count=count,
                           categories=categories)


@app.route("/description/<int:item_id>/<string:source>")
def show_description(item_id, source):
    item = session.query(Item).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=item.category_id).one()
    return render_template("description.html",
                           item=item,
                           category=category,
                           source=source)


@app.route("/new_category", methods=['GET', 'POST'])
def new_category():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = Category(name=request.form['name'],
                            user_id=login_session['user_id'])
        session.add(category)
        session.commit()
        flash('Category successfully added')
        return redirect(url_for("main"))
    else:
        categories = getCategories()
        return render_template("new_category.html", categories=categories)


@app.route("/new_item", methods=['GET', 'POST'])
def new_item():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category_id = request.form['cat']
        item_to_add = Item(
            name=request.form['name'],
            category_id=category_id,
            description=request.form['description'],
            user_id=login_session['user_id']
        )
        session.add(item_to_add)
        session.commit()
        flash('Item successfully added')
        return redirect(url_for("main"))
    else:
        categories = getCategories()
        return render_template("new_item.html", categories=categories)


@app.route("/edit_category/<int:category_id>", methods=['GET', 'POST'])
def edit_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    cat_to_edit = session.query(Category).filter_by(id=category_id).one()
    user_id = cat_to_edit.user_id
    if user_id == login_session['user_id']:
        if request.method == 'POST':
            if request.form['name']:
                cat_to_edit.name = request.form['name']
            session.add(cat_to_edit)
            session.commit()
            flash("Category successfully edited")
            return redirect(url_for("main"))
        else:
            return render_template("edit_category.html", category=cat_to_edit)
    else:
        flash("You can only edit categories you created!")
        return redirect(url_for("main"))


@app.route("/edit_item/<int:item_id>", methods=['GET', 'POST'])
def edit_item(item_id):
    if 'username' not in login_session:
        return redirect('/login')
    item_to_edit = session.query(Item).filter_by(id=item_id).one()
    user_id = item_to_edit.user_id
    if user_id == login_session['user_id']:
        if request.method == 'POST':
            if request.form['name']:
                item_to_edit.name = request.form['name']
            if request.form['description']:
                item_to_edit.description = request.form['description']
            if request.form['cat']:
                item_to_edit.category_id = request.form['cat']
            session.add(item_to_edit)
            session.commit()
            flash("Item successfully edited")
            return redirect(url_for("main"))
        else:
            categories = getCategories()
            return render_template("edit_item.html",
                                   categories=categories,
                                   item=item_to_edit)
    else:
        flash("You can only edit items you created!")
        return redirect(url_for("main"))


@app.route("/delete_category/<int:category_id>", methods=['GET', 'POST'])
def delete_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    user_id = category.user_id
    if user_id == login_session['user_id']:
        if request.method == 'POST':
            session.delete(category)
            session.commit()
            flash('Category successfully deleted')
            return redirect(url_for('main'))
        else:
            return render_template("delete_category.html", category=category)
    else:
        flash("You can only delete categories you created!")
        return redirect(url_for("main"))


@app.route("/delete_item/<int:item_id>", methods=['GET', 'POST'])
def delete_item(item_id):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(id=item_id).one()
    user_id = item.user_id
    if user_id == login_session['user_id']:
        if request.method == 'POST':
            session.delete(item)
            session.commit()
            flash('Item successfully deleted')
            return redirect(url_for('main'))
        else:
            return render_template("delete_item.html", item=item)
    else:
        flash("You can only delete items you created!")
        return redirect(url_for("main"))


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
