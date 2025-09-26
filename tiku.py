
import json
import sqlite3
import os
from typing import List, Dict, Any, Optional

DB_FILE = 'tk.db'

# ---------- 内部工具 ----------
def _get_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def _init_table():
    sql = '''
    CREATE TABLE IF NOT EXISTS question (
        id          TEXT PRIMARY KEY,   -- 原 JSON 中的 ID
        caption     TEXT,               -- 题干
        options     TEXT,               -- JSON 序列化后的选项 dict
        answer      TEXT,               -- 标准答案（单选:A  多选:A|B|C  判断:Y/N）
        qtype       TEXT,               -- radio / check / yn
        remark      TEXT                -- 原 ReMark
    );
    '''
    with _get_conn() as conn:
        conn.execute(sql)

def _clear_table():
    with _get_conn() as conn:
        conn.execute('DELETE FROM question')

def _guess_qtype(rec: dict) -> str:
    """根据字段特征判断题型"""
    if rec.get('YorNCount'):          # 判断题
        return 'yn'
    if rec.get('CheckCount'):         # 多选题
        return 'check'
    return 'radio'                    # 默认单选

def _norm_answer(raw: str, qtype: str) -> str:
    """把答案统一成单字符、|分隔、Y/N"""
    raw = raw.strip()
    if qtype == 'yn':
        return raw.upper()            # Y/N
    if qtype == 'check':
        return '|'.join(sorted(raw.upper().split('|')))  # A|B|C
    return raw.upper()                # 单选 A/B/C/...

# ---------- 对外接口 ----------
def load_folder(folder: str):
    """
    批量导入一个文件夹下的所有 .json 题库
    例：load_folder('./jsons')
    """
    _init_table()
    _clear_table()          # 如想增量导入，可去掉本行
    files = [os.path.join(folder, f) for f in os.listdir(folder) if f.lower().endswith('.json')]
    if not files:
        raise FileNotFoundError('目录下未发现 .json 文件')
    for fp in files:
        with open(fp, encoding='utf-8') as f:
            data = json.load(f)
        with _get_conn() as conn:
            for sect in ('A', 'B', 'C'):        # 单选/多选/判断
                arr = data.get(sect, [])
                if not isinstance(arr, list):
                    continue
                for item in arr:
                    qtype = _guess_qtype(data) if sect == 'C' else ('check' if sect == 'B' else 'radio')
                    opt_dict = {k: item[k] for k in item if k.startswith('option') and item[k]}
                    conn.execute(
                        'INSERT OR REPLACE INTO question(id,caption,options,answer,qtype,remark) VALUES (?,?,?,?,?,?)',
                        (item['ID'], item['Caption'], json.dumps(opt_dict, ensure_ascii=False),
                         _norm_answer(item['AnSwer'], qtype), qtype, item.get('ReMark', ''))
                    )


def get_by_id(qid: str) -> dict:
    """
    按 ID 精准查询
    存在 -> 返回字典
    不存在 -> 返回 {'error': '题库中不存在 ID=xxx 的记录'}
    """
    with _get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            'SELECT id,caption,options,answer,qtype,remark FROM question WHERE id=?',
            (qid,)
        ).fetchone()
    if row:
        return dict(row)
    return {'error': f'题库中不存在 ID={qid} 的记录'}
def update_answer(qid: str, new_answer: str):
    """
    更新标准答案
    例：update_answer('2', 'C')
    """
    with _get_conn() as conn:
        conn.execute('UPDATE question SET answer=? WHERE id=?', (new_answer, qid))

# ---------- 演示 ----------
if __name__ == '__main__':
    # 1. 导入
    load_folder('./jsons')          # 把你的 json 全放这个文件夹
    # 2. 查询
    res = get_by_id('1')
    print(res)
    # 3. 更新
    # update_answer('2', 'B')
