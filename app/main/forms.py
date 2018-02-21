# -*- coding: UTF-8 -*-

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField,\
    SubmitField
from wtforms.validators import Required, Length, Email, Regexp
from wtforms import ValidationError
from flask_pagedown.fields import PageDownField
from ..models import Role, User


class NameForm(FlaskForm):
    name = StringField(u'用户名', validators=[Required()])
    submit = SubmitField(u'提交')


class EditProfileForm(FlaskForm):
    name = StringField(u'真实名字', validators=[Length(0, 64)])
    location = StringField(u'地址', validators=[Length(0, 64)])
    about_me = TextAreaField(u'关于我')
    submit = SubmitField(u'提交')


class EditProfileAdminForm(FlaskForm):
    email = StringField(u'邮件地址', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField(u'用户名', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    confirmed = BooleanField(u'已验证')
    role = SelectField(u'角色', coerce=int)
    name = StringField(u'真实名字', validators=[Length(0, 64)])
    location = StringField(u'地址', validators=[Length(0, 64)])
    about_me = TextAreaField(u'关于我')
    submit = SubmitField(u'提交')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class PostForm(FlaskForm):
    body = PageDownField(u"你想说的：", validators=[Required()])
    submit = SubmitField(u'提交')


class CommentForm(FlaskForm):
    body = StringField(u'输入评论', validators=[Required()])
    submit = SubmitField(u'提交')
