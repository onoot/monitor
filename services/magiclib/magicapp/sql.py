from magicapp import app
from urllib.parse import urlparse
import psycopg2
import logging


logger = logging.getLogger(__name__)


class db:
    def __init__(self):
        cs = urlparse(app.config["POSTGRES_CONNECT"])
        self.conn = psycopg2.connect(dbname=cs.path[1:],
                               user=cs.username,
                               password=cs.password,
                               host=cs.hostname,
                               port=cs.port)
        self.conn.autocommit = True

    def init_db(self):
        with self.conn.cursor() as cursor:
            cursor.execute(open("magicapp/schema.sql", "r").read())

    def get_all_users(self):
        results = []
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT * FROM magic")
            results = cursor.fetchall()
        if results == [] or results[0] == []:
            results = None
        return results

    def get_user_by_id(self, userid):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT * FROM magic WHERE id = %s", (userid,))
                result = cursor.fetchone()
            return result
        except Exception as e:
            logger.error(f"Error getting user by id {userid}: {e}")
            return None

    def get_user_by_name(self, username):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT * FROM magic WHERE username = %s", (username,))
                result = cursor.fetchone()
                app.logger.debug(f"DB query result for {username}: {result}")
            return result  # Возвращает кортеж или None
        except Exception as e:
            logger.error(f"Error getting user by name {username}: {e}")
            return None

    def insert_user(self, username, password, magicword):
        results = None
        with self.conn.cursor() as cursor:
            cursor.execute("INSERT INTO magic (username, password, magicword) VALUES (%s, %s, %s) RETURNING id", (username, password, magicword ))
            results = cursor.fetchone()[0]
        return results
    def is_user_admin(self, user_id):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT is_admin FROM magic WHERE id = %s", (user_id,))
                result = cursor.fetchone()
                return result and result[0]  # Возвращает True если is_admin = True
        except Exception as e:
            logger.error(f"Error checking admin status for user {user_id}: {e}")
            return False
