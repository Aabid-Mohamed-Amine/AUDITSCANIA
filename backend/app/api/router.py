from fastapi import APIRouter
from app.api import scans, websocket, auth, pipeline

api_router = APIRouter()

api_router.include_router(auth.router,     prefix="/auth",     tags=["auth"])
api_router.include_router(scans.router,    prefix="/scans",    tags=["scans"])
api_router.include_router(websocket.router,                    tags=["websocket"])
api_router.include_router(pipeline.router, prefix="/pipeline", tags=["pipeline"])
