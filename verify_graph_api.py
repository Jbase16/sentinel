import asyncio
import logging
from httpx import AsyncClient
from core.server.api import app
from core.data.db import Database
from core.base.config import get_config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VerifyGraphAPI")

async def main():
    # 1. Initialize DB to find a valid session
    db = Database.instance()
    await db.init()
    
    # Get latest session with graph nodes
    cursor = await db.execute("""
        SELECT session_id, count(*) as c, MAX(created_at) as last_seen 
        FROM graph_nodes 
        GROUP BY session_id 
        ORDER BY last_seen DESC 
        LIMIT 1
    """)
    row = await cursor.fetchone()
    
    if not row:
        logger.error("❌ No sessions found with graph nodes! Cannot verify endpoint.")
        return

    session_id = row[0]
    count = row[1]
    logger.info(f"✅ Found session {session_id} with {count} nodes.")

    # 2. Test API Endpoint using direct app access
    config = get_config()
    token = config.security.api_token
    headers = {"Authorization": f"Bearer {token}"}
    
    from httpx import ASGITransport
    transport = ASGITransport(app=app)
    
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Fetch Graph
        logger.info(f"Fetching graph for session: {session_id}")
        resp = await client.get(f"/v1/graph?session_id={session_id}", headers=headers)
        
        if resp.status_code == 200:
            data = resp.json()
            logger.info("✅ API Request Successful")
            logger.info(f"Response Keys: {data.keys()}")
            logger.info(f"Node Count (API): {data['count']['nodes']}")
            logger.info(f"Edge Count (API): {data['count']['edges']}")
            
            # Verify data integrity
            if data['count']['nodes'] == count:
                 logger.info("✅ Node count matches database.")
            else:
                 logger.warning(f"⚠️ Node count mismatch! DB: {count}, API: {data['count']['nodes']}")
                 
            # Print a sample node to verify structure
            if data['nodes']:
                logger.info(f"Sample Node: {data['nodes'][0]}")
                
        else:
            logger.error(f"❌ API Request Failed: {resp.status_code} - {resp.text}")

if __name__ == "__main__":
    asyncio.run(main())
