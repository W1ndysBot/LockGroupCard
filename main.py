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
            "CREATE TABLE LockGroupCard ("
            "user_id TEXT, "
            "group_id TEXT, "
            "group_card TEXT, "
            "is_locked BOOLEAN, "
            "UNIQUE(user_id, group_id)"
            ")"
        )
        conn.commit()
        conn.close()
        logging.info(f"初始化LockGroupCard数据库成功")


# 锁定群名片
def lock_group_card(group_id, user_id, group_card):
    db_path = os.path.join(DATA_DIR, "LockGroupCard.db")
    if os.path.exists(db_path):
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO LockGroupCard (user_id, group_id, group_card, is_locked) VALUES (?, ?, ?, TRUE)",
                (user_id, group_id, group_card),
            )
            logging.info(
                f"[群名片锁] 群[{group_id}]的[{user_id}]的群名片为[{group_card}]已写入或更新数据库"
            )
            conn.commit()
            return True
    else:
        logging.error(f"LockGroupCard数据库不存在，初始化数据库")
        init_db()
        return False


# 解锁群名片
def unlock_group_card(group_id, user_id):
    db_path = os.path.join(DATA_DIR, "LockGroupCard.db")
    if os.path.exists(db_path):
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE LockGroupCard SET is_locked = FALSE WHERE user_id = ? AND group_id = ?",
                (user_id, group_id),
            )
            logging.info(
                f"[群名片锁] 群[{group_id}]的[{user_id}]的群名片已从数据库中解锁"
            )
            conn.commit()
            return True
    else:
        logging.error(f"LockGroupCard数据库不存在，初始化数据库")
        init_db()
        return False


# 管理群名片锁
async def manage_LockGroupCard(
    websocket, group_id, user_id, role, message_id, raw_message
):
    try:
        if not is_authorized(role, user_id) and raw_message.startswith("lgc"):
            await send_group_msg(
                websocket,
                group_id,
                "[CQ:reply,id=" + message_id + "] 你没有权限执行管理群名片锁操作",
            )
            return

        if raw_message == "lgcon":
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

        elif raw_message == "lgcoff":
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
        if not load_LockGroupCard(group_id) and raw_message.startswith("lgc"):
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}]群名片锁未开启，无法执行操作",
            )
            return

        elif raw_message.startswith("lgclock"):
            match = re.match(r"lgclock\[CQ:at,qq=([0-9]+)\](.*)", raw_message)
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
                        f"[CQ:reply,id={message_id}][CQ:at,qq={user_id}] 群名片锁已锁定，群名片已锁定为[{group_card}]",
                    )
                else:
                    await send_group_msg(
                        websocket,
                        group_id,
                        f"[CQ:reply,id={message_id}][CQ:at,qq={user_id}] 群名片锁锁定失败",
                    )
        elif raw_message.startswith("lgcunlock"):
            match = re.match(r"lgcunlock\[CQ:at,qq=([0-9]+)\]", raw_message)
            if match:
                user_id = match.group(1)
                unlock_group_card(group_id, user_id)
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}][CQ:at,qq={user_id}] 群名片锁已解锁",
                )
        elif raw_message.startswith("lgcset"):
            # 加斜杠是为了转义，防止正则表达式解析错误，[0-9]+ 表示一个或多个数字，不需要转义，但是cq码就是需要匹配的字符，需要转义
            match = re.match(r"lgcset\[CQ:at,qq=([0-9]+)\](.*)", raw_message)
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
                + "lgcon 开启群名片锁\n"
                + "lgcoff 关闭群名片锁\n"
                + "lgclock+@+群名片 锁定群名片\n"
                + "lgcunlock+@ 解锁群名片\n"
                + "lgcset+@+群名片 修改群名片",
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
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:at,qq={user_id}] 检测到群名片被锁且与数据库不一致，群名片已由[{group_card}]修改为[{group_card_in_db}]",
            )
            logging.info(
                f"[群名片锁]检测到群[{group_id}]的[{user_id}]的群名片不符合数据库，已自动修改为[{group_card_in_db}]"
            )


# 群名片锁菜单
async def LockGroupCard(websocket, group_id, message_id):
    message = (
        f"[CQ:reply,id={message_id}]\n"
        + """
群名片锁

lgcon 开启群名片锁
lgcoff 关闭群名片锁
lgclock@+群名片 锁定群名片
lgcunlock@ 解锁群名片
lgcset@+群名片 修改群名片
"""
    )
    await send_group_msg(websocket, group_id, message)


# 群消息处理函数
async def handle_LockGroupCard_group_message(websocket, msg):
    try:
        user_id = str(msg.get("user_id"))
        group_id = str(msg.get("group_id"))
        raw_message = str(msg.get("raw_message"))
        role = str(msg.get("sender", {}).get("role"))
        message_id = str(msg.get("message_id"))
        group_card = str(msg.get("sender", {}).get("card"))

        if raw_message == "lockgroupcard":
            await LockGroupCard(websocket, group_id, message_id)

        asyncio.gather(
            manage_LockGroupCard(
                websocket, group_id, user_id, role, message_id, raw_message
            ),
            handle_user_group_card_lock(websocket, group_id, user_id, group_card),
        )

    except Exception as e:
        logging.error(f"处理LockGroupCard群消息失败: {e}")
        return


# 统一事件处理入口
async def handle_events(websocket, msg):
    """统一事件处理入口"""
    post_type = msg.get("post_type", "response")  # 添加默认值
    try:
        # 处理回调事件
        if msg.get("status") == "ok":
            return

        post_type = msg.get("post_type")

        # 处理元事件
        if post_type == "meta_event":
            return

        # 处理消息事件
        elif post_type == "message":
            message_type = msg.get("message_type")
            if message_type == "group":
                await handle_LockGroupCard_group_message(websocket, msg)
            elif message_type == "private":
                return

        # 处理通知事件
        elif post_type == "notice":
            return

    except Exception as e:
        error_type = {
            "message": "消息",
            "notice": "通知",
            "request": "请求",
            "meta_event": "元事件",
        }.get(post_type, "未知")

        logging.error(f"处理群名片锁{error_type}事件失败: {e}")

        # 发送错误提示
        if post_type == "message":
            message_type = msg.get("message_type")
            if message_type == "group":
                await send_group_msg(
                    websocket,
                    msg.get("group_id"),
                    f"处理群名片锁{error_type}事件失败，错误信息：{str(e)}",
                )
