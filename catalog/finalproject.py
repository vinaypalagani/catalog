from flask import (
    Flask,
    flash,
    render_template,
    request,
    url_for,
    redirect,
    make_response,
    jsonify
)
import sys

from sqlalchemy import Column, ForeignKey, Integer, String

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import relationship

from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import backref

from sqlalchemy import desc
from sqlalchemy import create_engine
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
import os
import random
import string
import httplib2
import json
import requests
from flask import session as login_session
app = Flask(__name__)
CLIENT_ID = json.loads(open("client_secrets.json", 'r').read())
CLIENT_ID = CLIENT_ID['web']['client_id']

Base = declarative_base()


class Admin(Base):
    __tablename__ = "admin"
    admin_id = Column(Integer, primary_key=True)
    admin_mail = Column(String(100), nullable=False)


class Sport(Base):
    __tablename__ = "sport"
    sport_id = Column(Integer, primary_key=True)
    sport_name = Column(String(100), nullable=False)
    sport_admin = Column(Integer, ForeignKey('admin.admin_id'))
    sport_relation = relationship(Admin)


class Items(Base):
    __tablename__ = "items"
    item_id = Column(Integer, primary_key=True)
    item_name = Column(String(100), nullable=False)
    item_price = Column(Integer, nullable=False)
    item_weight = Column(Integer, nullable=False)
    item_brand = Column(String(100), nullable=False)
    item_agegroup = Column(String(100), nullable=False)
    item_salepackage = Column(Integer, nullable=False)
    item_image = Column(String(1000), nullable=False)
    sport_id = Column(Integer, ForeignKey('sport.sport_id'))
    item_relation = relationship(
        Sport,
        backref=backref("items", cascade="all, delete")
        )

    @property
    def serialize(self):
        return {
            'item_name': self.item_name,
            'price': self.item_price,
            'weight': self.item_weight,
            'brand': self.item_brand,
            'agegroup': self.item_agegroup,
            'salepackage': self.item_salepackage,
            'image': self.item_image
        }


# end of line
engine = create_engine('sqlite:///sports.db')
Base.metadata.create_all(engine)

session = scoped_session(sessionmaker(bind=engine))


@app.route('/contact')
def contact():
    return render_template('contact.html')


# home page
@app.route('/home')
def home():
    items = session.query(Items).order_by(desc(Items.item_id)).limit(4).all()
    if items:
        return render_template('home.html', items=items)
    return render_template('home.html', items=None)


# shows category list
@app.route('/category', methods=['GET'])
def showcategory():
    if request.method == 'GET':
        category_list = session.query(Sport).all()
        return render_template('scategory.html', categories=category_list)


# adds new category
@app.route('/category/new', methods=['GET', 'POST'])
def newcategory():
    if 'email'not in login_session:
        flash("please login to add category")
        return redirect(url_for('home'))
    admin = session.query(
        Admin
        ).filter_by(
        admin_mail=login_session['email']
        ).one_or_none()
    if not admin:
        flask('invalid admin')
        return redirect(url_for('showcategory'))
    if request.method == 'GET':
        return render_template('new_category.html')
    else:
        category_name = request.form['category_name']
        if category_name:
            admin_id = admin.admin_id
            new_sport = Sport(sport_name=category_name, sport_admin=admin_id)
            session.add(new_sport)
            session.commit()
            flash('added category '+str(category_name))
            return redirect(url_for('showcategory'))
        else:
            flash("unable to add category")
            return redirect(url_for('home'))


# edits category
@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editcategory(category_id):
    if 'email'not in login_session:
        flash("please login to edit category")
        return redirect(url_for('home'))
    admin = session.query(Admin).filter_by(
        admin_mail=login_session['email']
        ).one_or_none()
    if not admin:
        flash('invalid user')
        return redirect(url_for('home'))
    sport = session.query(Sport).filter_by(sport_id=category_id).one_or_none()
    if not sport:
        flash('no such category')
        return redirect(url_for('home'))
    login_admin_id = admin.admin_id
    admin_id = sport.sport_admin
    if login_admin_id != admin_id:
        flash('you are not allowed to edit this category')
        return redirect(url_for('showcategory'))
    if request.method == 'POST':
        category_name = request.form['category_name']
        sport.sport_name = category_name
        session.add(sport)
        session.commit()
        flash('category updated successfully')
        return redirect(url_for('showcategory'))
    else:
        sport = session.query(Sport).filter_by(
            sport_id=category_id
            ).one_or_none()
        return render_template(
            'edit_category.html',
            sport_name=sport.sport_name,
            id_category=category_id
        )


# delete category
@app.route('/category/<int:category_id>/delete')
def deletecategory(category_id):
    if 'email'not in login_session:
        flash("please login to delete category")
        return redirect(url_for('home'))
    admin = session.query(Admin).filter_by(
        admin_mail=login_session['email']
        ).one_or_none()
    if not admin:
        flash('invalid user')
        return redirect(url_for('home'))
    sport = session.query(Sport).filter_by(sport_id=category_id).one_or_none()
    if not sport:
        flash('no such category')
        return redirect(url_for('home'))
    login_admin_id = admin.admin_id
    admin_id = sport.sport_admin
    if login_admin_id != admin_id:
        flash('you are not allowed to delete this category')
        return redirect(url_for('showcategory'))
    name = sport.sport_name
    session.delete(sport)
    session.commit()
    flash('deleted category '+str(name))
    return redirect(url_for('showcategory'))


@app.route('/category/<int:categoryid>/items')
def showitems(categoryid):
    items = session.query(Items).filter_by(sport_id=categoryid).all()
    return render_template(
        'showitems.html',
        cat_id=categoryid,
        item=items
        )


@app.route('/category/<int:categoryid>/items.json')
def showitemsJson(categoryid):
    items = session.query(Items).filter_by(sport_id=categoryid).all()
    return jsonify(items=[item.serialize for item in items])


@app.route('/items.json')
def showAllitemsJson():
    items = session.query(Items).all()
    return jsonify(items=[item.serialize for item in items])


@app.route(
    '/category/<int:category_id>/items/<int:itemid>',
    methods=['GET', 'POST']
)
def itemdetails(category_id, itemid):
    if request.method == 'GET':
        item = session.query(Items).filter_by(
            sport_id=category_id,
            item_id=itemid
            ).one_or_none()
        isUserLogin = True
        return render_template(
            'item_details.html',
            isUserLogin=isUserLogin,
            iname=item.item_name,
            iprice=item.item_price,
            iweight=item.item_weight,
            ibrand=item.item_brand,
            agegroup=item.item_agegroup,
            ipackage=item.item_salepackage,
            image=item.item_image
        )


@app.route('/category/<int:categoryid>/items/new', methods=['GET', 'POST'])
def newitem(categoryid):
    if 'email'not in login_session:
        flash("please login to add item")
        return redirect(url_for('home'))
    admin = session.query(
        Admin
        ).filter_by(
        admin_mail=login_session['email']
        ).one_or_none()
    if not admin:
        flash('invalid user')
        return redirect(url_for('home'))
    category = session.query(Sport).filter_by(
        sport_id=categoryid
        ).one_or_none()
    if not category:
        flash('invalid category')
        return redirect(url_for('showcategory'))
    login_admin_id = admin.admin_id
    admin_id = category.sport_admin
    if login_admin_id != admin_id:
        flash("not allowed to add item in this category")
        return redirect(url_for('showitems', categoryid=categoryid))
    if request.method == 'GET':
        return render_template('additem.html', cat_id=categoryid)
    else:
        name = request.form['iname']
        image = request.form['iimage']
        price = int(request.form['iprice'])
        weight = int(request.form['iweight'])
        brand = request.form['ibrand']
        agegroup = request.form['iagegroup']
        salepackage = int(request.form['isalepackage'])
        sid = categoryid
        new_item = Items(
            item_name=name,
            item_price=price,
            item_weight=weight,
            item_brand=brand,
            item_agegroup=agegroup,
            item_salepackage=salepackage,
            item_image=image,
            sport_id=sid
        )
        session.add(new_item)
        session.commit()
        flash('item added successfully')
        return redirect(url_for('showitems', categoryid=categoryid))


@app.route(
    '/category/<int:categoryid>/items/<int:itemid>/edit',
    methods=['GET', 'POST']
)
def edititem(categoryid, itemid):
    if 'email'not in login_session:
        flash("please login to edit item")
        return redirect(url_for('home'))
    admin = session.query(
        Admin
        ).filter_by(
        admin_mail=login_session['email']
        ).one_or_none()
    if not admin:
        flash('invalid user')
        return redirect(url_for('showcategory'))
    category = session.query(
        Sport
        ).filter_by(
        sport_id=categoryid
        ).one_or_none()
    if not category:
        flash('invalid category')
        return redirect(url_for('showcategory'))
    item = session.query(
        Items
        ).filter_by(
        sport_id=categoryid, item_id=itemid
        ).one_or_none()
    if not item:
        flash('invalid item')
        return redirect(url_for('showcategory'))
    login_admin_id = admin.admin_id
    admin_id = category.sport_admin
    if login_admin_id != admin_id:
        flash("not allowed to edit item in this category")
        return redirect(url_for('showitems', categoryid=categoryid))
    if request.method == 'POST':
        name = request.form['iname']
        image = request.form['iimage']
        price = int(request.form['iprice'])
        weight = int(request.form['iweight'])
        brand = request.form['ibrand']
        agegroup = request.form['iagegroup']
        salepackage = int(request.form['isalepackage'])
        item = session.query(
            Items
            ).filter_by(
            sport_id=categoryid, item_id=itemid
            ).one_or_none()
        if item:
            item.item_name = name
            item.item_image = image
            item.item_price = price
            item.item_weight = weight
            item.item_brand = brand
            item.item_agegroup = agegroup
            item.item_salepackage = salepackage
        else:
            return 'no items'
        session.add(item)
        session.commit()
        flash('item updated')
        return redirect(
            url_for('itemdetails', category_id=categoryid, itemid=itemid)
            )
    else:
        edit = session.query(
            Items
            ).filter_by(
            item_id=itemid
            ).one_or_none()
        if edit:
            return render_template(
                'edit_item.html',
                iname=edit.item_name,
                iprice=edit.item_price,
                iweight=edit.item_weight,
                ibrand=edit.item_brand,
                iagegroup=edit.item_agegroup,
                isalepackage=edit.item_salepackage,
                iimage=edit.item_image,
                catid=categoryid,
                iid=itemid
                )
        else:
            return 'no elements'


@app.route('/category/<int:categoryid>/items/<int:itemid>/delete')
def deleteitem(categoryid, itemid):
    if 'email'not in login_session:
        flash("please login to delete item")
        return redirect(url_for('showcategory'))
    admin = session.query(
        Admin
        ).filter_by(
        admin_mail=login_session['email']
        ).one_or_none()
    if not admin:
        flash('invalid user')
        return redirect(url_for('showcategory'))
    category = session.query(
        Sport
        ).filter_by(
        sport_id=categoryid
        ).one_or_none()
    if not category:
        flash('invalid category')
        return redirect(url_for('showcategory'))
    item = session.query(
        Items
        ).filter_by(
        sport_id=categoryid, item_id=itemid
        ).one_or_none()
    if not item:
        flash('item not found')
        return redirect(url_for('showcategory'))
    login_admin_id = admin.admin_id
    admin_id = category.sport_admin
    if login_admin_id != admin_id:
        flash("not allowed to delete item in this category")
        return redirect(url_for('showitems', categoryid=categoryid))
    item = session.query(
        Items
        ).filter_by(
        item_id=itemid
        ). one_or_none()
    name = item.item_name
    session.delete(item)
    session.commit()
    flash('deleted item '+str(name))
    return redirect(url_for('showitems', categoryid=categoryid))


# login routing
@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# it helps the user to loggedin and display flash profile

# GConnect


@app.route('/gconnect', methods=['POST', 'GET'])
def gConnect():
    if request.args.get('state') != login_session['state']:
        response.make_response(json.dumps('Invalid State paramenter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    request.get_data()
    code = request.data.decode('utf-8')

    # Obtain authorization code

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps("""Failed to upgrade the authorisation code"""),
            401
            )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.

    access_token = credentials.access_token
    myurl = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'
    myurl = myurl.format(str(access_token))
    header = httplib2.Http()
    result = json.loads(header.request(myurl, 'GET')[1].decode('utf-8'))

    # If there was an error in the access token info, abort.

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
                            """Token's user ID does not
                            match given user ID."""),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            """Token's client ID
            does not match app's."""),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200
            )
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    # ADD PROVIDER TO LOGIN SESSION

    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    admin_id = get_admin_id(login_session['email'])
    if not admin_id:
        admin_id = create_admin(login_session['email'])
    login_session['admin_id'] = admin_id
    flash("user login successfully")
    return "login successfully"


def create_admin(mail):
    email = mail
    newAdmin = Admin(admin_mail=email)
    session.add(newAdmin)
    session.commit()
    admin = session.query(Admin).filter_by(admin_mail=email).first()
    adminId = admin.admin_id
    return adminId


def get_admin_id(admin_mail):
    try:
        admin = session.query(Admin).filter_by(admin_mail=admin_mail).one()
        return admin.admin_id
    except Exception as e:
        print(e)
        return None

# Gdisconnect


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401
            )
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    header = httplib2.Http()
    result = header.request(url, 'GET')[0]

    if result['status'] == '200':

        # Reset the user's session.

        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['email']
        response = redirect(url_for('home'))
        response.headers['Content-Type'] = 'application/json'
        flash(" user logged out", "success")
        return response
    else:

        # if given token is invalid, unable to revoke token
        response = make_response(json.dumps('Failed to revoke token for user'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/glogout')
def glogout():
    isLogin = False
    try:
        login_session['email']
        isLogin = True
    except Exception as e:
        isLogin = False
    if isLogin:
        return gdisconnect()
    else:
        flash('no user logged in')
        return redirect(url_for('home'))


if __name__ == '__main__':
    app.secret_key = "secretkey@123"
    app.run(debug=True, host="localhost", port=5000)
