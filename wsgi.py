from werkzeug.middleware.dispatcher import DispatcherMiddleware
from app import app


def simple(env, resp):
    resp(b'200 OK', [('Content-Type', 'text/plain')])
    return [b'Hello WSGI World']


app.config["APPLICATION_ROOT"] = "/ivan"
app.wsgi_app = DispatcherMiddleware(simple, {'/ivan': app.wsgi_app})


if __name__ == '__main__':
    app.run()
