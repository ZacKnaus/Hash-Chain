import asyncio
import logging
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
import smtplib
import email
from email.parser import BytesParser
from email.policy import default
import hashlib
import sqlite3
import datetime


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logging; use INFO or WARNING to reduce verbosity
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler("smtp_proxy.log"),  # Log to a file
        logging.StreamHandler()  # Also output to console
    ]
)

logger = logging.getLogger(__name__)


# Global configuration variables
DESTINATION_SMTP_SERVER = 'actual.smtp.server.goes.here'
DESTINATION_SMTP_PORT = 587
DESTINATION_SMTP_USERNAME = 'usernamegoeshere'
DESTINATION_SMTP_PASSWORD = 'supersecretpassword'
USE_TLS = True  # Set to False if the destination server doesn't use TLS

# SQLite database file
BLOCKCHAIN_DB = 'blockchain.db'


# Initialize the blockchain database
def init_blockchain_db():
    logger.debug('Initializing blockchain database.')
    conn = sqlite3.connect(BLOCKCHAIN_DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS blockchain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            previous_hash TEXT,
            current_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    logger.debug('Blockchain database initialized.')

# Get the last hash in the blockchain
def get_last_hash():
    logger.debug('Fetching last hash from blockchain.')
    conn = sqlite3.connect(BLOCKCHAIN_DB)
    c = conn.cursor()
    c.execute('SELECT current_hash FROM blockchain ORDER BY id DESC LIMIT 1')
    result = c.fetchone()
    conn.close()
    last_hash = result[0] if result else None
    logger.debug(f'Last hash: {last_hash}')
    return last_hash

# Add a new block to the blockchain
def add_block_to_chain(current_hash, previous_hash):
    logger.debug('Adding new block to blockchain.')
    conn = sqlite3.connect(BLOCKCHAIN_DB)
    c = conn.cursor()
    timestamp = datetime.datetime.utcnow().isoformat()
    c.execute('''
        INSERT INTO blockchain (timestamp, previous_hash, current_hash)
        VALUES (?, ?, ?)
    ''', (timestamp, previous_hash, current_hash))
    conn.commit()
    conn.close()
    logger.info(f'New block added to blockchain with current_hash: {current_hash} and previous_hash: {previous_hash}')

# SMTP handler class
class SMTPProxyHandler:
    async def handle_DATA(self, server, session, envelope):
        logger.debug('Received email data.')
        try:
            # Get the raw email content
            email_bytes = envelope.content  # This is a bytes object containing the email

            # Parse the email message
            email_message = email.message_from_bytes(email_bytes, policy=default)
            logger.debug('Email message parsed successfully.')

            # Compute the hash of the email content
            email_hash = hashlib.sha256(email_bytes).hexdigest()
            logger.info(f'Email hash computed: {email_hash}')

            # Get the previous hash
            previous_hash = get_last_hash() or 'None'  # Use 'None' if no previous hash exists
            logger.debug(f'Previous hash: {previous_hash}')

            # Add the hash to the blockchain
            add_block_to_chain(email_hash, previous_hash)

            # Add the hashes as headers to the email
            email_message['X-Email-Hash'] = email_hash
            email_message['X-Email-Previous-Hash'] = previous_hash
            logger.debug('Added X-Email-Hash and X-Email-Previous-Hash headers to email.')

            # Optionally, add a timestamp
            # timestamp = datetime.datetime.utcnow().isoformat() + 'Z'  # Adding 'Z' to indicate UTC
            # email_message['X-Email-Timestamp'] = timestamp
            # logger.debug(f'Added X-Email-Timestamp header: {timestamp}')

            # Convert the email message back to bytes
            modified_email_bytes = email_message.as_bytes()
            logger.debug('Modified email converted back to bytes.')

            # Forward the email to the destination SMTP server
            await self.forward_email(modified_email_bytes, email_message)

            return '250 OK'

        except Exception as e:
            logger.exception(f'Error handling message: {e}')
            return '451 Internal server error'

    async def forward_email(self, email_bytes, email_message):
        logger.debug('Preparing to forward email to destination SMTP server.')
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.send_email, email_bytes, email_message)

    def send_email(self, email_bytes, email_message):
        try:
            if USE_TLS:
                logger.debug('Establishing TLS connection to destination SMTP server.')
                server = smtplib.SMTP(DESTINATION_SMTP_SERVER, DESTINATION_SMTP_PORT)
                server.starttls()
            else:
                logger.debug('Connecting to destination SMTP server without TLS.')
                server = smtplib.SMTP(DESTINATION_SMTP_SERVER, DESTINATION_SMTP_PORT)

            # Login if credentials are provided
            if DESTINATION_SMTP_USERNAME and DESTINATION_SMTP_PASSWORD:
                logger.debug('Logging in to destination SMTP server.')
                server.login(DESTINATION_SMTP_USERNAME, DESTINATION_SMTP_PASSWORD)

            # Send the email
            sender = email_message['From']
            recipients = email_message.get_all('To', []) + email_message.get_all('Cc', []) + email_message.get_all('Bcc', [])
            logger.debug(f'Sending email from {sender} to {recipients}')
            server.sendmail(sender, recipients, email_bytes)
            server.quit()
            logger.info('Email forwarded successfully.')
        except Exception as e:
            logger.exception(f'Error forwarding email: {e}')

# Main function to start the SMTP proxy server
def main():
    init_blockchain_db()
    handler = SMTPProxyHandler()
    controller = Controller(handler, hostname='127.0.0.1', port=2525)
    controller.start()
    logger.info('SMTP proxy server running on port 2525...')
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        logger.info('SMTP proxy server shutting down.')
    finally:
        controller.stop()
        logger.debug('SMTP proxy server stopped.')

if __name__ == '__main__':
    main()
