from datetime import datetime
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from markdown import markdown
import bleach
from flask import current_app, request, url_for
from flask.ext.login import UserMixin, AnonymousUserMixin
from app.exceptions import ValidationError
from . import db, login_manager


class Permission:
    READ = 0x01
    BILLING = 0x02
    SEND_MESSAGES = 0x04
    ADD_APP = 0x08
    ADMINISTER = 0x16
    SUPER_ADMIN = 0x80


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'Company Owner': (Permission.READ |
                              Permission.BILLING |
                              Permission.SEND_MESSAGES |
                              Permission.ADD_APP,
                              Permission.ADMINISTRATOR, True),
            'Company Dev': (Permission.READ |
                            Permission.ADD_APP, False),
            'Company Marketing': (Permission.READ |
                                  Permission.SEND_MESSAGES, False),
            'Super Admin': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class Company(db.Model):
    __tablename__ = 'companies'
    apps = db.relationship('App', backref='publisher', lazy='dynamic')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'))

    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))

    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
        self.followed.append(Follow(followed=self))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True

    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('ascii')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class App(db.Model):
    __tablename__ = 'apps'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        company_count = Company.query.count()
        for i in range(count):
            u = Company.query.offset(randint(0, company_count - 1)).first()
            p = App(name=forgery_py.full_name(),
                    timestamp=forgery_py.date.date(True),
                    company=u)
            db.session.add(p)
            db.session.commit()


class Device(db.Model):
    __tablename__ = 'devices'
    """
    Represents an iPhone used to push

    device_token - the iPhone Unique Push Identifier (64 chars of hex)
    last_notified_at - when was a notification last sent to the phone
    test_phone - is this a phone that should be included in test runs
    meta - just a small notes field so that we can put in things like "Lee's iPhone"
    failed_phone - Have we had feedback about this phone? If so, flag it.
    failed_count - consecutive failed pushes.  So that it can be removed and not tried again.
    """
    device_token = db.Column(db.String(64))
    gc_token =db.Column(db.String(256))
    player_name = db.Column(db.String(128))
    last_notified_at = db.Column(db.DateTime, default=datetime.utcnow)
    test_phone = db.Column(db.Boolean, default=False, index=True)
    meta = db.Column(db.Text)
    failed_phone = db.Column(db.Boolean, default=False, index=True)
    failed_count = db.Column(db.Integer, default=0)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'))
    app_id = db.Column(db.Integer, db.ForeignKey('apps.id'))


# class ComplexAlert(models.Model):
#     sandbox = models.BooleanField()
#     user = models.ForeignKey(User)
#     app = models.ForeignKey(App)
#     body = models.CharField(max_length=200)
#     badge = models.IntegerField(default=0)
#     sound = models.CharField(max_length=32, null=True, blank=True)
#     action_loc_key = models.CharField(max_length=100, null=True, blank=True)
#     loc_key = models.CharField(max_length=100, null=True, blank=True)
#     loc_args = models.CharField(max_length=200, null=True, blank=True)
#     custom_params = models.CharField(max_length=200, null=True, blank=True)
#
#     def __unicode__(self):
#         return "%s %s" % (self.app.name, self.body)


# class SimpleAlert(models.Model):
#     sandbox = models.BooleanField()
#     user = models.ForeignKey(User)
#     app = models.ForeignKey(App)
#     message = models.CharField(max_length=200)
#     badge = models.IntegerField(default=0)
#     sound = models.CharField(max_length=16, choices=(('chime', 'chime'),))
#
#     def __unicode__(self):
#         return "%s %s" % self.app.name, self.message
