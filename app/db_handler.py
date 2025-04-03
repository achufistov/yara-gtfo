import sqlite3
from sqlite3 import Error

def create_connection(db_file):
    """ Создает соединение с SQLite базе данных """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return conn

def create_table(conn):
    """ Создает таблицу для хранения бинарных файлов """
    try:
        sql_create_binaries_table = """ CREATE TABLE IF NOT EXISTS binaries (
                                            id integer PRIMARY KEY,
                                            path text NOT NULL,
                                            exploit_info text
                                        ); """
        cursor = conn.cursor()
        cursor.execute(sql_create_binaries_table)
    except Error as e:
        print(e)

def insert_binary(conn, binary):
    """ Вставляет бинарный файл в таблицу """
    sql = ''' INSERT INTO binaries(path, exploit_info)
              VALUES(?, ?) '''
    cur = conn.cursor()
    cur.execute(sql, binary)
    conn.commit()
    return cur.lastrowid

def get_all_binaries(conn):
    """ Получает все бинарные файлы из таблицы """
    cur = conn.cursor()
    cur.execute("SELECT * FROM binaries")

    rows = cur.fetchall()
    return rows