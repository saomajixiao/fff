# -*- coding: UTF-8 -*-

from flask import render_template, redirect, url_for, abort, flash, request,\
    current_app, make_response, session
from flask_login import login_required, current_user
from flask_sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, PostForm,\
    CommentForm
from .. import db
from ..models import Permission, Role, User, Post, Comment, Collect
from ..decorators import admin_required, permission_required


@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASKY_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response


@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'


@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(body=form.body.data,
                    author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    session['current_url'] = request.url
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.followed_posts
    else:
        query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts,
                           show_followed=show_followed, pagination=pagination)


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    session['current_url'] = request.url
    collection_times = sum(post.collectors.count() for post in user.posts.all())
    if not request.args.get('show_collection'):
        pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        posts = pagination.items
        return render_template('user.html', user=user, posts=posts,
                            pagination=pagination, collection_times=collection_times)
    else:
        pagination = user.collections.order_by(Collect.timestamp.desc()).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        posts = [item.post for item in pagination.items]
        return render_template('user.html', user=user, posts=posts,
                pagination=pagination, collection_times=collection_times,show_collection=True)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash(u'你的资料已更新.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash(u'资料已更新.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          author=current_user._get_current_object())
        db.session.add(comment)
        flash(u'你的评论已提交.')
        return redirect(url_for('.post', id=post.id))
    page = request.args.get('page', 1, type=int)
    session['current_url'] = request.url
    session['current_path'] = request.path
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form,
                           comments=comments, pagination=pagination)


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash(u'文章已更新.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)


@main.route('/delete_post/<int:id>')
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    current_user.delete_post(post)
    flash(u'你删除了一篇文章')
    if session.get('current_url') and (session.get('current_path') != ('/post/%d' % id)):
        return redirect(session.get('current_url'))
    else:
        return redirect(url_for('.user', username=current_user.username))


@main.route('/delete_comment/<int:id>')
@login_required
def delete_comment(id):
    comment = Comment.query.get_or_404(id)
    if current_user != comment.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    current_user.delete_comment(comment)
    flash(u'你删除了一条评论')
    if session.get('current_url'):
        return redirect(session.get('current_url'))
    else:
        return redirect(url_for('.post', id=comment.post_id))


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOWCOLLECT)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(u'无效用户.')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash(u'你已关注此用户.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash(u'你关注了 %s.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOWCOLLECT)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(u'无效用户.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash(u'你没有关注此用户.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash(u'你取消了对 %s 的关注.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(u'无效用户.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title=u"的粉丝",
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(u'无效用户.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title=u"的关注",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)


@main.route('/collect/<int:id>')
@login_required
@permission_required(Permission.FOLLOWCOLLECT)
def collect(id):
    post = Post.query.filter_by(id=id).first()
    if post is None:
        flash(u'无效文章.')
        if session.get('current_url'):
            return redirect(session.get('current_url'))
        else:
            return redirect(url_for('.index'))
    elif current_user.is_collecting(post):
        flash(u'你已收藏此文章.')
    else:
        current_user.collect(post)
        flash(u'你收藏了 %s 的一篇文章.' % post.author.username)
    if session.get('current_url'):
        return redirect(session.get('current_url'))
    else:
        return redirect(url_for('.post', id=id))


@main.route('/uncollect/<int:id>')
@login_required
@permission_required(Permission.FOLLOWCOLLECT)
def uncollect(id):
    post = Post.query.filter_by(id=id).first()
    if post is None:
        flash(u'无效文章.')
        if session.get('current_url'):
            return redirect(session.get('current_url'))
        else:
            return redirect(url_for('.index'))
    elif not current_user.is_collecting(post):
        flash(u'你没有收藏此文章.')
    else:
        current_user.uncollect(post)
        flash(u'你取消了对 %s 的一篇文章的收藏.' % post.author.username)
    if session.get('current_url'):
        return redirect(session.get('current_url'))
    else:
        return redirect(url_for('.post', id=id))


@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                           pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))
