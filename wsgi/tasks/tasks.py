from celery import Celery

celery = Celery('tasks', broker='amqp://guest:123456@dannernaytion.com:5672')


@celery.task(name='tasks.register_user')
def register_user(data):
    pass


@celery.task(name='tasks.send_confirm_email', bind=True)
def send_confirm_email(self, *args, **kwargs):
    pass


@celery.task(name='tasks.confirm_user')
def confirm_user(email):
    pass


@celery.task(name='tasks.add_contact')
def add_contact(self, **kwargs):
    pass



@celery.task(name='tasks.recover_password')
def recover_password(email):
    print email

    pass

@celery.task(name='tasks.reset_password')
def reset_password(email, password):
    print email

    pass

def test():
    from celery import chain
    user_mock = dict(password='mynameis', u_name='Melvin',
                     email='dannernaytion@gmail.com', f_name='Melvin', l_name='Harris', bun='devuser0002')
    chain(register_users.s(str(user_mock)),
          send_confirm_email.s()).apply_async()
