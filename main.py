# script/LockGroupCard/main.py


import logging
import os
import sys
import sqlite3
import asyncio
import re

# 添加项目根目录到sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from app.config import owner_id
from app.api import *
from app.switch import load_switch, save_switch


DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "LockGroupCard",
)


# 检查是否是群主
def is_group_owner(role):
    return role == "owner"


# 检查是否是管理员
def is_group_admin(role):
    return role == "admin"


# 检查是否有权限（管理员、群主或root管理员）
def is_authorized(role, user_id):
    is_admin = is_group_admin(role)
    is_owner = is_group_owner(role)
    return (is_admin or is_owner) or (user_id in owner_id)


# 查看功能开关状态
def load_LockGroupCard(group_id):
    return load_switch(group_id, "群名片锁")


# 保存功能开关状态
def save_LockGroupCard(group_id, status):
    save_switch(group_id, "群名片锁", status)


# 读取用户在数据库中的群名片
def load_user_group_card(group_id, user_id):
    db_path = os.path.join(DATA_DIR, "LockGroupCard.db")
    if os.path.exists(db_path):
        with sqlite3.connect(db_path) as conn:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT group_card FROM LockGroupCard WHERE user_id = ? AND group_id = ? AND is_locked = TRUE",
                (user_id, group_id),
            )
            result = cursor.fetchone()

            if result:
                conn.close()
                return str(result[0])  # 返回元组中的第一个元素

    else:
        logging.error(f"LockGroupCard数据库不存在，初始化数据库")
        init_db()
        return False


# 初始化数据库
def init_db():
    # 确保数据目录存在
    os.makedirs(DATA_DIR, exist_ok=True)

    # 初始化数据库（仅在数据库文件不存在时执行）
    db_path = os.path.join(DATA_DIR, "LockGroupCard.db")
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "CREATE TABLE LockGroupCard (user_id TEXT, group_id TEXT, group_card TEXT, is_locked BOOLEAN)"
        )
        conn.commit()
        conn.close()
        logging.info(f"初始化LockGroupCard数据库成功")


# 锁定群名片
def lock_group_card(group_id, user_id, group_card):
    db_path = os.path.join(DATA_DIR, "LockGroupCard.db")
    if os.path.exists(db_path):
        with sqlite3.connect(db_path) as conn:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            if load_user_group_card(group_id, user_id):
                cursor.execute(
                    "UPDATE LockGroupCard SET group_card = ? WHERE user_id = ? AND group_id = ? AND is_locked = TRUE",
                    (group_card, user_id, group_id),
                )
                logging.info(
                    f"[群名片锁] 群[{group_id}]的[{user_id}]的群名片为[{group_card}]已更新数据库"
                )
            else:
                cursor.execute(
                    "INSERT INTO LockGroupCard (user_id, group_id, group_card, is_locked) VALUES (?, ?, ?, TRUE)",
                    (user_id, group_id, group_card),
                )
                logging.info(
                    f"[群名片锁] 群[{group_id}]的[{user_id}]的群名片为[{group_card}]已写入数据库"
                )
            conn.commit()
            conn.close()
            return True
    else:
        logging.error(f"LockGroupCard数据库不存在，初始化数据库")
        init_db()
        return False


# 解锁群名片
def unlock_group_card(group_id, user_id):
    db_path = os.path.join(DATA_DIR, "LockGroupCard.db")
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE LockGroupCard SET is_locked = FALSE WHERE user_id = ? AND group_id = ?",
            (user_id, group_id),
        )
        logging.info(f"[群名片锁] 群[{group_id}]的[{user_id}]的群名片已从数据库中解锁")
        conn.commit()
        conn.close()


# 管理群名片锁
async def manage_LockGroupCard(
    websocket, group_id, user_id, role, message_id, raw_message
):
    try:
        if not is_authorized(role, user_id) and raw_message.startswith("lgc-"):
            await send_group_msg(
                websocket,
                group_id,
                "[CQ:reply,id=" + message_id + "] 你没有权限执行管理群名片锁操作",
            )
            return

        if raw_message == "lgc-on":
            if load_LockGroupCard(group_id):
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}]群名片锁已开启，无需重复开启",
                )
            else:
                save_LockGroupCard(group_id, True)
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}]群名片锁已开启",
                )
            return

        elif raw_message == "lgc-off":
            if load_LockGroupCard(group_id):
                save_LockGroupCard(group_id, False)
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}]群名片锁已关闭",
                )
            else:
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}]群名片锁已关闭，无需重复关闭",
                )
            return

        # 检查群名片锁是否开启
        if not load_LockGroupCard(group_id) and raw_message.startswith("lgc-"):
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}]群名片锁未开启，无法执行操作",
            )
            return

        elif raw_message.startswith("lgc-lock"):
            match = re.match(r"lgc-lock\[CQ:at,qq=([0-9]+)\](.*)", raw_message)
            if match:
                user_id = match.group(1)
                group_card = match.group(2).strip()
                if lock_group_card(group_id, user_id, group_card):
                    await set_group_card(
                        websocket,
                        group_id,
                        user_id,
                        group_card,
                    )
                    await send_group_msg(
                        websocket,
                        group_id,
                        f"[CQ:reply,id={message_id}][CQ:at,qq={user_id}] 群名片锁已锁定",
                    )
                else:
                    await send_group_msg(
                        websocket,
                        group_id,
                        f"[CQ:reply,id={message_id}][CQ:at,qq={user_id}] 群名片锁锁定失败",
                    )
        elif raw_message.startswith("lgc-unlock"):
            match = re.match(r"lgc-unlock\[CQ:at,qq=([0-9]+)\]", raw_message)
            if match:
                user_id = match.group(1)
                unlock_group_card(group_id, user_id)
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}][CQ:at,qq={user_id}] 群名片锁已解锁",
                )
        elif raw_message.startswith("lgc-set"):
            # 加斜杠是为了转义，防止正则表达式解析错误，[0-9]+ 表示一个或多个数字，不需要转义，但是cq码就是需要匹配的字符，需要转义
            match = re.match(r"lgc-set\[CQ:at,qq=([0-9]+)\](.*)", raw_message)
            if match:
                user_id = match.group(1)
                group_card = match.group(2).strip()
                await set_group_card(
                    websocket,
                    group_id,
                    user_id,
                    group_card,
                )
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}][CQ:at,qq={user_id}] 群名片已修改为[{group_card}]",
                )

        elif raw_message.startswith("lgc"):
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}]群名片锁命令错误\n"
                + "lgc-on 开启群名片锁\n"
                + "lgc-off 关闭群名片锁\n"
                + "lgc-lock+@+群名片 锁定群名片\n"
                + "lgc-unlock+@ 解锁群名片\n"
                + "lgc-set+@+群名片 修改群名片",
            )
    except Exception as e:
        logging.error(f"处理LockGroupCard管理命令失败: {e}")
        return


# 处理用户群名片锁
async def handle_user_group_card_lock(websocket, group_id, user_id, group_card):
    group_card_in_db = load_user_group_card(group_id, user_id)
    # logging.info(f"群名片锁数据库返回值:{group_card_in_db}")
    # logging.info(f"群名片锁当前群名片:{group_card}")

    # 检查群名片锁是否开启
    if not load_LockGroupCard(group_id):
        return

    # 检查群名片是否符合数据库
    if group_card_in_db:
        if group_card != group_card_in_db:
            await set_group_card(
                websocket,
                group_id,
                user_id,
                group_card_in_db,
            )
            logging.info(
                f"[群名片锁]检测到群[{group_id}]的[{user_id}]的群名片不符合数据库，已自动修改为[{group_card_in_db}]"
            )


# 群消息处理函数
async def handle_LockGroupCard_group_message(websocket, msg):
    try:
        user_id = str(msg.get("user_id"))
        group_id = str(msg.get("group_id"))
        raw_message = str(msg.get("raw_message"))
        role = str(msg.get("sender", {}).get("role"))
        message_id = str(msg.get("message_id"))
        group_card = str(msg.get("sender", {}).get("card"))

        asyncio.gather(
            manage_LockGroupCard(
                websocket, group_id, user_id, role, message_id, raw_message
            ),
            handle_user_group_card_lock(websocket, group_id, user_id, group_card),
        )

    except Exception as e:
        logging.error(f"处理LockGroupCard群消息失败: {e}")
        return
