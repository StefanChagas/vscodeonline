from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status, Form, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
import requests
from reportlab.pdfgen import canvas
import json
from typing import Union, List
from pydantic import BaseModel, ValidationError
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import JWTError, jwt
from secrets import token_hex
from base64 import b64encode
import mysql.connector
from mysql.connector import (connection)
import os
import uvicorn

SECRET_KEY = "b4ba722bc24d72f910d37357912420d221e9c53b2444c9cc5a756fa27e893a98"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 630   

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class TokenDataHash(BaseModel):
    hashed_password: Union[str, None] = None

class User(BaseModel):
    username: str
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None

class UserDB(User):
    hashed_password:str

class DeleteProduct(BaseModel):
    codigo: str

class Valuemodify(BaseModel):
    material: Union[str, None] = None
    novo_valor: Union[str, None] = None

class Baseallproduct(BaseModel):
    codigo: Union[str, None] = None
    nome: Union[str, None] = None
    material: Union[str, None] = None
    quantidade_material: Union[float, None] = None
    imposto: Union[float, None] = None
    imposto_dois: Union[str, None] = None
    horas_cnc: Union[float, None] = None
    horas_plaina: Union[float, None] = None
    horas_fresa: Union[float, None] = None
    horas_furadeira: Union[float, None] = None
    horas_serra_fita: Union[float, None] = None
    horas_solda: Union[float, None] = None
    zincagem: Union[float, None] = None
    valor: Union[float, None] = None
    estoque: Union[float, None] = None
    frete: Union[str, None] = None

class Baseadduser(BaseModel):
    nome: str
    senha: str

class Basemodifyproducts(BaseModel):
    last_codigo: Union[str, None] = None
    valornovo: Union[str, None] = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_pass(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_hash_pass(password):                
    return pwd_context.hash(password) 

def get_user_pass(db,username: str):   
    if username in db:
        user_dict = db[username]
        return UserDB(**user_dict)

def authentic_user(fake_db, username: str, password: str):   
    user = get_user_pass(fake_db, username)
    if not user:
        return False
    if not verify_pass(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas, por favor, faça login novamente.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try: 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        hash_for_token: str = payload.get("hash_for_token")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
        token_data_hash = TokenDataHash(hashed_password=hash_for_token)
    except JWTError:
        raise credentials_exception

    fake_users_db ={
            token_data.username:{
                "username": token_data.username,
                "hashed_password": token_data_hash.hashed_password, 
                "disabled": False
            }
        }
    
    user = get_user_pass(fake_users_db, username=token_data.username)   

    if user is None:
        raise credentials_exception
    return user

async def get_active_user(current_user: User = Security(get_current_user, scopes=["me"])):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="inativo")
    return current_user

@app.post("/token/{user_type}", response_model=Token)
async def login_with_token(user_type, form_data: OAuth2PasswordRequestForm = Depends()):    
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    if (user_type == "user_admin"):
        cursor.execute("SELECT password FROM users_adm WHERE nome = '%s'" %(form_data.username))
        sql = cursor.fetchall()
        sqlpass = sql[0]
        sqlpass = sqlpass[0]
        verificacao = verify_pass(form_data.password, sqlpass)
        if verificacao == True:
            fake_users_db ={
                form_data.username:{
                    "username": form_data.username,
                    "hashed_password": sqlpass, 
                    "disabled": False
                }
            }
            var_user_type = "useradmin"
    elif (user_type == "user_basic"):
        cursor.execute("SELECT password FROM users_basic WHERE nome = '%s'" %(form_data.username))
        sqlbasic = cursor.fetchall()
        sqlbasic = sqlbasic[0]
        sqlbasic = sqlbasic[0]
        verificacao = verify_pass(form_data.password, sqlbasic)
        if verificacao == True:
            fake_users_db ={
                form_data.username:{
                    "username": form_data.username,
                    "hashed_password": sqlbasic, 
                    "disabled": False
                }
            }
            var_user_type = "userbasic"
    else:
        return False

    user = authentic_user(fake_users_db, form_data.username, form_data.password)     
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "hash_for_token": fake_users_db[form_data.username]['hashed_password'], "scopes": form_data.scopes}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user_type": var_user_type} # , "user_type": var_user_type

# fim auth ----

# deletar material
@app.post("/delete/material/{material}")
async def delete_material(material, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    material = material.replace("_", " ")
    material = material.replace("-", "ç")
    material = material.lower()
    sql = "DELETE FROM valor_materiais WHERE material = '%s'" %(material)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"

# deletar frete
@app.post("/delete/frete/{frete}")
async def delete_frete(frete, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    frete = frete.replace("_", " ")
    frete = frete.replace("-", "ç")
    frete = frete.lower()
    sql = "DELETE FROM valor_fretes WHERE frete = '%s'" %(frete)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"

# deletar produto
@app.post("/delete/product/{produto}")
async def delete_product(produto, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    produto = produto.replace("_", " ")
    produto = produto.replace("-", "ç")
    sql = "DELETE FROM products WHERE codigo = '%s'" %(produto)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Produto apagado!"

# deletar usuário limitado
@app.post("/delete/user/basic/{name}")
async def delete_user_basic(name, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    name = name.replace("_", " ")
    name = name.replace("-", "ç")
    sql = "DELETE FROM users_basic WHERE nome = '%s'" %(name)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"

# deletar usuário admin
@app.post("/delete/user/admin/{name}")
async def delete_user_admin(name, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    name = name.replace("_", " ")
    name = name.replace("-", "ç")
    sql = "DELETE FROM users_adm WHERE nome = '%s'" %(name)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"

# registrar produto
@app.post("/registration/product")
async def add_product(produto: Baseallproduct): # , current_user: User = Depends(get_active_user)
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    
    resultpayload = json.loads(produto.json())
    i_codigo = resultpayload['codigo']
    i_nome_peca = resultpayload['nome'].lower()
    i_material = resultpayload['material'].lower()
    i_quantidade_material = resultpayload['quantidade_material']
    i_imposto = resultpayload['imposto']
    i_impostodois = resultpayload['imposto_dois']
    i_horas_cnc = resultpayload['horas_cnc']
    i_horas_plaina = resultpayload['horas_plaina']
    i_horas_fresa = resultpayload['horas_fresa']
    i_horas_furadeira = resultpayload['horas_furadeira']
    i_horas_serra_fita = resultpayload['horas_serra_fita']
    i_horas_solda = resultpayload['horas_solda']
    i_zincagem = resultpayload['zincagem']
    i_valor_final = resultpayload['valor']
    i_estoque = resultpayload['estoque']
    i_frete = resultpayload['frete'].lower()

    sql = "INSERT INTO products (codigo, nome_peca, material, quantidade_material, imposto, impostodois, quantidade_horas_cnc, quantidade_horas_plaina, quantidade_horas_fresa, quantidade_horas_furadeira, quantidade_horas_serra_fita, quantidade_horas_solda, zincagem, valor_final, estoque, frete) VALUES ('%s','%s','%s', '%s','%s','%s', '%s','%s','%s','%s','%s', '%s','%s','%s', '%s', '%s')" %(i_codigo, i_nome_peca, i_material, i_quantidade_material, i_imposto, i_impostodois, i_horas_cnc, i_horas_plaina, i_horas_fresa, i_horas_furadeira, i_horas_serra_fita, i_horas_solda, i_zincagem, i_valor_final, i_estoque, i_frete)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "produto adicionado!"

# registrar material
@app.post("/registration/material/{material}/{value}")
async def add_material(material, value, current_user: User = Depends(get_active_user)): 
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    material = material.lower()
    material = material.replace("_", " ")
    material = material.replace("-", "ç")
    material = material.lower()
    sql = "INSERT INTO valor_materiais (material, valor_material) VALUES ('%s','%s')" %(material, value)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"

# registrar frete
@app.post("/registration/frete/{frete}/{value}")
async def add_frete(frete, value, current_user: User = Depends(get_active_user)): 
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    frete = frete.lower()
    frete = frete.replace("_", " ")
    frete = frete.replace("-", "ç")
    frete = frete.lower()
    sql = "INSERT INTO valor_fretes (frete, valor_frete) VALUES ('%s','%s')" %(frete, value)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"

# adicionar usuário BÁSICOS com hash inserida no banco, sem hash somada com algo mais para maior segurança
@app.post("/registration/users/basic")
async def insert_user_basic(payload: Baseadduser):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    resultpayload = json.loads(payload.json())
    i_password = get_hash_pass(resultpayload['senha'])
    sql="INSERT INTO users_basic (nome, password) VALUES ('%s','%s')" %(resultpayload['nome'], i_password)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Usuário com escopo limitado adicionado!"

# adicionar novo administrador
# @app.post("/registration/users/admin")
# async def insert_user_admin(nome, senha):
#     db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
#     cursor = db_connection.cursor()
#     payload = json.loads(payload.json())
#     i_password = get_hash_pass(senha)
#     sql="INSERT INTO users_adm (nome, password) VALUES ('%s','%s')" %(nome, i_password)
#     cursor.execute(sql)
#     db_connection.commit()
#     db_connection.close()
#     return "Usuário administrador adicionado!"

# listar tabela do imposto dos estados do Brasil 
@app.post("/list/state/value")
async def listar_imposto_maquinas(current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM valor_imposto_estados")
    sql = cursor.fetchall()
    return sql

# listar tabela hora máquinas 
@app.post("/list/machine/value")
async def listar_maquinas(current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM valor_maquinas")
    sql = cursor.fetchall()
    return sql

# listar tabela materiais 
@app.post("/list/material/value")
async def listar_materiais(current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM valor_materiais")
    sql = cursor.fetchall()
    return sql

# listar tabela fretes 
@app.post("/list/frete/value")
async def listar_fretes(current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM valor_fretes")
    sql = cursor.fetchall()
    return sql

# listar todos os produtos
@app.post("/list/products/all")
async def listar_produtos(current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM products")
    sql = cursor.fetchall()
    return sql

# gerar pdf com lista completa de produtos
@app.post("/list/pdf/products/{state}")
async def list_to_pdf(state, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM products")
    sql = cursor.fetchall()

    try:
        nome_pdf = "listagem_produtos_Usine"
        pdf = canvas.Canvas('{}.pdf'.format(nome_pdf))
        x = 760
        # date = datetime.date.today()
        pdf.setTitle(nome_pdf)
        pdf.setFont("Helvetica", 14)
        pdf.drawString(10,820, 'Lista de produtos - Usine Metalúrgica')
        pdf.setFont("Helvetica", 7)
        # pdf.drawString(15,805, '%s' %(date)) 
        pdf.drawString(10,770, 'Código | Código Usine | Nome | Material | Quantidade de Material | CNC | Plaina | Fresa | Furadeira | Serra Fita | Solda | Zincagem | Tratamento Térmico | Frete | Imposto | Valor Final | Estoque')
        for i in range(len(sql)): 
            if i > 0:
                contador = i + 1
            else:
                contador = 1 
            codigo = sql[i][0]
            nome = sql[i][1]
            material = sql[i][2]
            quantidade_material = sql[i][3]
            imposto = sql[i][4]
            codigo_usine = sql[i][5]
            cnc = sql[i][6]
            plaina = sql[i][7]
            fresa = sql[i][8]
            furadeira = sql[i][9]
            serra_fita = sql[i][10]
            solda = sql[i][11]
            zincagem = sql[i][12]
            tratamento_termico = sql[i][13] 
            estoque = sql[i][14]
            frete = sql[i][15]
            valor_final = 123
            x -= 20
            pdf.setFont("Helvetica", 8)
            pdf.drawString(10,x, '{} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {}'.format(contador, codigo, codigo_usine, nome, material, quantidade_material, cnc, plaina, fresa, furadeira, serra_fita, solda, zincagem, tratamento_termico, frete, imposto, valor_final, estoque))
            y = 36
            if i == y:
                pdf.showPage()
                x = 820
                y = y+5
                y = y*2
        pdf.save()
        print('pdf criado com sucesso!')
        return ("pdf criado com sucesso!")
    except:
        print('Erro ao gerar o pdf.')
        return ("Erro ao gerar o pdf.")

# gerar pdf com lista para o distribuidor de produtos
@app.post("/list/pdf/products/distributor")
async def list_to_pdf_distributor(current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM products")
    sql = cursor.fetchall()

    try:
        nome_pdf = "listagem_produtos_distribuidor_Usine"
        pdf = canvas.Canvas('{}.pdf'.format(nome_pdf))
        x = 760
        # date = datetime.date.today()
        pdf.setTitle(nome_pdf)
        pdf.setFont("Helvetica", 14)
        pdf.drawString(15,820, 'Lista de produtos - Usine Metalúrgica')
        pdf.setFont("Helvetica", 12)
        # pdf.drawString(15,805, '%s' %(date)) 
        pdf.drawString(15,770, 'Código | Nome | Valor')
        for i in range(len(sql)): 
            if i > 0:
                contador = i + 1
            else:
                contador = 1 
            codigo = sql[i][0]
            nome = sql[i][1]
            material = sql[i][2]
            quantidade_material = sql[i][3]
            imposto = sql[i][4]
            codigo_usine = sql[i][5]
            cnc = sql[i][6]
            plaina = sql[i][7]
            fresa = sql[i][8]
            furadeira = sql[i][9]
            serra_fita = sql[i][10]
            solda = sql[i][11]
            zincagem = sql[i][12]
            tratamento_termico = sql[i][13] 
            estoque = sql[i][14]
            frete = sql[i][15]
            valor_final = 123
            x -= 20
            pdf.setFont("Helvetica", 12)
            pdf.drawString(15,x, '{} | {} | {} | {}'.format(contador, codigo, codigo_usine, nome, valor_final, estoque))
            y = 36
            if i == y:
                pdf.showPage()
                x = 820
                y = y+5
                y = y*2
        pdf.save()
        print('pdf criado com sucesso!')
        return ("pdf criado com sucesso!")
    except:
        print('Erro ao gerar o pdf.')
        return ("Erro ao gerar o pdf.")

# alterar nome de usuário limitado
@app.post("/change/user/name/basic/{lastname}/{name}")
async def modify_user_basic_name(lastname, name, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE users_basic SET nome = '%s' WHERE nome = '%s'" %(name, lastname)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!" 

# alterar senha de usuário limitado
@app.post("/change/user/password/basic/{lastname}/{password}")
async def modify_user_basic_name(lastname, password, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE users_basic SET password = '%s' WHERE nome = '%s'" %(password, lastname)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!" 

# alterar nome de usuário admin
# @app.post("/change/user/name/admin/{lastname}/{name}")
# async def modify_user_admin_name(lastname, name, current_user: User = Depends(get_active_user)):
#     db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
#     cursor = db_connection.cursor()
#     sql = "UPDATE users_adm SET nome = '%s' WHERE nome = '%s'" %(name, lastname)
#     cursor.execute(sql)
#     db_connection.commit()
#     db_connection.close()
#     return "Ok!" 

# alterar valor da hora do CNC
@app.post("/change/value/cnc/{valor}")
async def alterar_valor_cnc(valor, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE valor_maquinas SET hora_cnc = '%s'" %(valor)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"    

# alterar valor da hora da Plaina
@app.post("/change/value/plaina/{valor}")
async def alterar_valor_plaina(valor, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE valor_maquinas SET hora_plaina = '%s'" %(valor)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"    

# alterar valor da hora da Fresa
@app.post("/change/value/fresa/{valor}")
async def alterar_valor_fresa(valor, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE valor_maquinas SET hora_fresa = '%s'" %(valor)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"  

# alterar valor da hora da Furadeira
@app.post("/change/value/furadeira/{valor}")
async def alterar_valor_furadeira(valor, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE valor_maquinas SET hora_furadeira = '%s'" %(valor)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"  

# alterar valor da hora da Serra Fita
@app.post("/change/value/serra/fita/{valor}")
async def alterar_valor_serra_fita(valor, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE valor_maquinas SET hora_serra_fita = '%s'" %(valor)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"  

# alterar valor da hora da Solda
@app.post("/change/value/solda/{valor}")
async def alterar_valor_solda(valor, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE valor_maquinas SET hora_solda = '%s'" %(valor)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"  

@app.post("/change/value/material/{material}/{value}")
async def alterar_valor_material(material, value, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    material = material.replace("_", " ")
    material = material.replace("-", "ç")
    material = material.lower()
    sql = "UPDATE valor_materiais SET valor_material = %s WHERE material = '%s'" %(value, material)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"  

@app.post("/change/value/state/imposto/{initial}/{value}")
async def alterar_valor_imposto_estados(initial, value, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    initial = initial.replace("_", " ")
    initial = initial.replace("-", "ç")
    initial = initial.lower()
    sql = "UPDATE valor_imposto_estados SET %s = %s" %(initial, value)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!"  

@app.post("/change/value/frete/{initial}/{value}")
async def alterar_valor_imposto_estados(initial, value, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    initial = initial.replace("_", " ")
    initial = initial.replace("-", "ç")
    initial = initial.lower()
    sql = "UPDATE valor_fretes SET valor_frete = %s WHERE frete = '%s'" %(value, initial)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!" 

#### modificações do produto -> 

# alterar código de um produto pelo CODIGO
@app.post("/change/with/code/code/{code}/{newvalue}")
async def alterar_codigo_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
        db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
        cursor = db_connection.cursor()
        sql = "UPDATE products SET codigo = %s WHERE codigo = '%s'" %(newvalue, code)
        cursor.execute(sql)
        db_connection.commit()
        db_connection.close()
        return sql 

# alterar nome de um produto pelo CODIGO
@app.post("/change/with/code/name/{code}/{newvalue}")
async def alterar_nome_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    newvalue = newvalue.replace("_", " ")
    newvalue = newvalue.replace("-", "ç")
    newvalue = newvalue.lower()
    sql = "UPDATE products SET nome_peca = '%s' WHERE codigo = '%s'" %(newvalue, code)        
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar material de um produto pelo CODIGO
@app.post("/change/with/code/material/{code}/{newvalue}")
async def alterar_material_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor() 
    newvalue = newvalue.lower()
    sql = "UPDATE products SET material = '%s' WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar quantidade material de um produto pelo CODIGO
@app.post("/change/with/code/quantidade/material/{code}/{newvalue}")
async def alterar_quantidade_material_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_material = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar imposto de um produto pelo CODIGO
@app.post("/change/with/code/imposto/{code}/{newvalue}")
async def alterar_imposto_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET imposto = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar imposto DOIS de um produto pelo CODIGO
@app.post("/change/with/code/impostodois/{code}/{newvalue}")
async def alterar_imposto_dois_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET impostodois = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora CNC pelo CODIGO
@app.post("/change/with/code/cnc/{code}/{newvalue}")
async def alterar__produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_cnc = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora plaina pelo CODIGO
@app.post("/change/with/code/plaina/{code}/{newvalue}")
async def alterar__produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_plaina = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora fresa pelo CODIGO
@app.post("/change/with/code/fresa/{code}/{newvalue}")
async def alterar__produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_fresa = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora furadeira pelo CODIGO
@app.post("/change/with/code/furadeira/{code}/{newvalue}")
async def alterar__produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_furadeira = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora serra fita pelo CODIGO
@app.post("/change/with/code/serra/fita/{code}/{newvalue}")
async def alterar__produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_serra_fita = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora solda pelo CODIGO
@app.post("/change/with/code/solda/{code}/{newvalue}")
async def alterar__produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_solda = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora zincagem pelo CODIGO
@app.post("/change/with/code/zincagem/{code}/{newvalue}")
async def alterar__produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET zincagem = '%s' WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql 

# alterar valor final de um produto pelo CODIGO
@app.post("/change/with/code/valor/final/{code}/{newvalue}")
async def alterar_valor_final_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET valor_final = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!" 

# alterar estoque de um produto pelo CODIGO
@app.post("/change/with/code/estoque/{code}/{newvalue}")
async def alterar_estoque_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET estoque = %s WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar frete de um produto pelo CODIGO
@app.post("/change/with/code/frete/{code}/{newvalue}")
async def alterar_frete_produto_with_code(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    newvalue = newvalue.lower()
    sql = "UPDATE products SET frete = '%s' WHERE codigo = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

#### modificações do produto UTILIZANDO código da Usine -> 

# alterar código de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/code/{code}/{newvalue}")
async def alterar_codigo_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
        db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
        cursor = db_connection.cursor()
        sql = "UPDATE products SET codigo = %s WHERE impostodois = '%s'" %(newvalue, code)
        cursor.execute(sql)
        db_connection.commit()
        db_connection.close()
        return sql 

# alterar nome de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/name/{code}/{newvalue}")
async def alterar_nome_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    newvalue = newvalue.replace("_", " ")
    newvalue = newvalue.replace("-", "ç")
    newvalue = newvalue.lower()
    sql = "UPDATE products SET nome_peca = '%s' WHERE impostodois = '%s'" %(newvalue, code)        
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar material de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/material/{code}/{newvalue}")
async def alterar_material_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor() 
    newvalue = newvalue.lower()
    sql = "UPDATE products SET material = '%s' WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar quantidade material de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/quantidade/material/{code}/{newvalue}")
async def alterar_quantidade_material_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_material = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar imposto de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/imposto/{code}/{newvalue}")
async def alterar_imposto_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET imposto = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar imposto DOIS de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/impostodois/{code}/{newvalue}")
async def alterar_imposto_dois_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET impostodois = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora CNC pelo CODIGO USINE
@app.post("/change/with/code/internal/cnc/{code}/{newvalue}")
async def alterar__produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_cnc = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora plaina pelo CODIGO USINE
@app.post("/change/with/code/internal/plaina/{code}/{newvalue}")
async def alterar__produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_plaina = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora fresa pelo CODIGO USINE
@app.post("/change/with/code/internal/fresa/{code}/{newvalue}")
async def alterar__produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_fresa = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora furadeira pelo CODIGO USINE
@app.post("/change/with/code/internal/furadeira/{code}/{newvalue}")
async def alterar__produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_furadeira = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora serra fita pelo CODIGO USINE
@app.post("/change/with/code/internal/serra/fita/{code}/{newvalue}")
async def alterar__produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_serra_fita = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora solda pelo CODIGO USINE
@app.post("/change/with/code/internal/solda/{code}/{newvalue}")
async def alterar__produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET quantidade_horas_solda = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar hora zincagem pelo CODIGO USINE
@app.post("/change/with/code/internal/zincagem/{code}/{newvalue}")
async def alterar__produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET zincagem = '%s' WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql 

# alterar valor final de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/valor/final/{code}/{newvalue}")
async def alterar_valor_final_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET valor_final = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return "Ok!" 

# alterar estoque de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/estoque/{code}/{newvalue}")
async def alterar_estoque_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    sql = "UPDATE products SET estoque = %s WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

# alterar frete de um produto pelo CODIGO USINE
@app.post("/change/with/code/internal/frete/{code}/{newvalue}")
async def alterar_frete_produto_with_code_internal(newvalue, code, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    newvalue = newvalue.lower()
    sql = "UPDATE products SET frete = '%s' WHERE impostodois = '%s'" %(newvalue, code)
    cursor.execute(sql)
    db_connection.commit()
    db_connection.close()
    return sql

#### fim das modificações do produto!

# pesquisar todos os produtos que usam um material igual (grupo de produtos com material igual) 
@app.post("/search/group/material/{nome}")
async def search_group_material(nome, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    nome = nome.lower()
    cursor.execute("SELECT * FROM products WHERE material = '%s'" %(nome))
    sql = cursor.fetchall()
    return sql

# pesquisar produto pelo codigo
@app.post("/search/code/product/{codigo}")
async def search_product_code(codigo, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    codigo = codigo.replace("_", " ")
    cursor.execute("SELECT * FROM products WHERE codigo = '%s'" %(codigo))
    sql = cursor.fetchall()
    return sql

# pesquisar produto pelo nome
@app.post("/search/name/product/{nome}")
async def search_product_name(nome, current_user: User = Depends(get_active_user)):
    db_connection = mysql.connector.connect(host='localhost', user='root', password='', database='allproducts')
    cursor = db_connection.cursor()
    nome = nome.replace("_", " ")
    nome = nome.replace("-", "ç")
    nome = nome.lower()
    cursor.execute("SELECT * FROM products WHERE nome_peca = '%s'" %(nome))
    sql = cursor.fetchall()
    return sql
