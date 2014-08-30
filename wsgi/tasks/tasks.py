from celery import Celery

celery = Celery('tasks', broker='amqp://guest:123456@107.170.146.210:5672')


@celery.task(name='tasks.register_user')
def register_users(data):
    pass


@celery.task(name='tasks.send_confirm_email', bind=True)
def send_confirm_email(self, *args, **kwargs):
    pass


@celery.task(name='confirm_user')
def confirm_user(self, id):
    pass


def test():
    from celery import chain
    user_mock=dict(password='mynameis', u_name='Melvin', email='dannernaytion@gmail.com', f_name='Melvin', l_name='Harris', bun='devuser0002')
    chain(register_users.s(str(user_mock)), send_confirm_email.s()).apply_async()
