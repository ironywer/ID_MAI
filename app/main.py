from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routers.main import router as main_router
from app.routers.encrypt import router as encrypt_router

app = FastAPI(title="PriceWatch — MVP")


app.mount("/static", StaticFiles(directory="static"), name="static")


app.include_router(main_router)
app.include_router(encrypt_router)


# app.include_router(api_products_router, prefix="/api", tags=["products"])