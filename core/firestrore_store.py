# core/firestore_store.py
import os, json, time, base64, hashlib
from google.cloud import firestore
from google.oauth2 import service_account

def init_firestore_from_service_account_json_str(sa_json_str: str):
    """
    Initialize a Firestore client using a service account JSON (string content).
    Returns a google.cloud.firestore.Client.
    """
    sa_info = json.loads(sa_json_str)
    creds = service_account.Credentials.from_service_account_info(sa_info)
    client = firestore.Client(credentials=creds, project=sa_info.get("project_id"))
    return client

def pubkey_fingerprint(pk_obj):
    """
    Compute deterministic fingerprint (hex) of a public key object (dict).
    """
    if isinstance(pk_obj, dict):
        raw = json.dumps(pk_obj, sort_keys=True).encode()
    else:
        raw = str(pk_obj).encode()
    return hashlib.sha256(raw).hexdigest()

def send_message(client, sender, sender_pk, recipients_pk_list, wraps, aes_dict, metadata=None):
    """
    Persist a message to Firestore. recipients_pk_list is a list of pk dicts.
    wraps is the wrapped-key list (one entry per recipient).
    aes_dict: {"nonce": "...", "ct": "..."}
    """
    col = client.collection("messages")
    recipients_fps = [pubkey_fingerprint(pk) for pk in recipients_pk_list]
    doc = {
        "sender": sender,
        "sender_pk_fp": pubkey_fingerprint(sender_pk) if sender_pk else None,
        "recipients_fps": recipients_fps,
        "wraps": wraps,
        "aes": aes_dict,
        "timestamp": time.time(),
        "metadata": metadata or {}
    }
    doc_ref = col.add(doc)
    return doc_ref

def fetch_messages_for_fingerprint(client, recipient_fp, limit=200):
    """
    Query messages addressed to recipient_fp (array_contains).
    Returns list of dicts sorted newest-first.
    """
    col = client.collection("messages")
    q = col.where("recipients_fps", "array_contains", recipient_fp).order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit)
    docs = q.stream()
    res = [d.to_dict() for d in docs]
    return res
