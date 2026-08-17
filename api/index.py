from mangum import Mangum

from app.database import init_db
from app.main import app

init_db()

handler = Mangum(app, lifespan="off")
