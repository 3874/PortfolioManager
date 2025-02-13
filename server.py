from flask import Flask, request, jsonify, render_template, session
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson.errors import InvalidId
from bson.binary import Binary
from datetime import datetime
import bcrypt, json
from jinja2.exceptions import TemplateNotFound
from functools import wraps
from bson import ObjectId
import numpy as np

with open('setting/config.json', 'r') as config_file:
    config = json.load(config_file)

app = Flask(__name__)
app.secret_key = config['SECRET_KEY']  # Change this in production!
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=config['SESSION_COOKIE_SECURE'],     # Set to True in production with HTTPS
    SESSION_COOKIE_SAMESITE='Lax'
)
PM_port = config['PM_PORT']

# MongoDB connection
client = MongoClient(config['MONGODB_URI'])
db = client[config['DB_NAME']]
AccessLevel = [{'role': 'admin', 'score': 0}, {'role': 'manager', 'score': 1}, {'role': 'editor', 'score': 2}, {'role': 'user', 'score': 3}]

# Collections
auth_access_collection = db['auth_collects']
securities_collection = db['securities']
users_collection = db['users']
funds_collection = db['funds']
companies_collection = db['companies']
transactions_collection = db['transactions']
investments_collection = db['investments']
contributions_collection = db['contributions']

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function
# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/<page_name>')
def render_page(page_name):
    try:
        return render_template(f'{page_name}.html')
    except TemplateNotFound:
        return "Page not found", 404
    
@app.route('/checkLoginStatus', methods=['GET'])
def check_login_status():
    if 'user_id' in session:
        return jsonify({'status': 'logged_in'})
    else:
        return jsonify({'status': 'not_logged_in'})

@app.route('/authenticateUser', methods=['POST'])
def authenticate_user():
    data = request.json

    if not data or 'ID' not in data or 'password' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400

    user = users_collection.find_one({'ID': data['ID']})
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    # Password verification
    stored_password = user['password']
    if isinstance(stored_password, Binary):
        hashed_bytes = stored_password.as_bytes()
    elif isinstance(stored_password, bytes):
        hashed_bytes = stored_password
    elif isinstance(stored_password, str):
        hashed_bytes = stored_password.encode('utf-8')
    else:
        return jsonify({'status': 'error', 'message': 'Invalid password format'}), 500

    if bcrypt.checkpw(data['password'].encode('utf-8'), hashed_bytes):
        # Check if user role is empty
        if not user.get('role'):
            return jsonify({'status': 'pending', 'message': 'User role is not assigned. contact to Admin.'}), 403
        
        session['user_id'] = str(user['_id'])
        return jsonify({'status': 'success', 'message': 'Login successful', 'userId': str(user['_id'])})
    
    return jsonify({'status': 'error', 'message': 'Invalid password'}), 401

@app.route('/signout', methods=['POST'])
@login_required
def logout():
    session.pop('user_id', None)
    return jsonify({'status': 'success', 'message': 'Logged out'})

@app.route('/getUsers', methods=['GET'])
@login_required
def get_users():
    if not check_access_level('users', session['user_id']):
        return jsonify({'status': 'error', 'data': 'no authority'}), 403
    
    try:
        # 사용자 정보를 가져오기 위한 쿼리
        users = list(users_collection.find())
        
        # 사용자 정보를 가공하여 반환할 데이터 형식으로 변환
        user_data = []
        for user in users:
            user_data.append({
                '_id': str(user['_id']),
                'ID': user.get('ID', ''),  # ID 필드
                'name': user.get('name', ''),  # 이름 필드
                'hire_date': user.get('hire_date', ''),  # 고용 날짜 필드
                'position': user.get('position', ''),  # 직위 필드
                'role': user.get('role', ''),  # 역할 필드
                'createdAt': user.get('createdAt', '').isoformat(),  # 생성 날짜
                'updatedAt': user.get('updatedAt', '').isoformat(),  # 업데이트 날짜
            })

        return jsonify({'status': 'success', 'data': user_data})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/addUser', methods=['POST'])
def add_user():
    try:
        data = request.json
        if not data or 'ID' not in data or 'password' not in data:
            return jsonify({'status': 'error', 'message': 'Missing fields'}), 400

        if users_collection.find_one({'ID': data['ID']}):
            return jsonify({'status': 'error', 'message': 'ID already exists'}), 400

        hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        user = {
            'ID': data['ID'],
            'password': Binary(hashed),
            'createdAt': datetime.now(),
            'updatedAt': datetime.now()
        }
        users_collection.insert_one(user)
        return jsonify({'status': 'success', 'message': 'User added'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/updateUser/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    try:
        data = request.json
        
        # 비밀번호가 없을 경우 비밀번호 업데이트를 생략
        update_fields = {
            'ID': data.get('ID', ''),
            'name': data.get('name', ''),
            'hire_date': data.get('hire_date', ''),
            'position': data.get('position', ''),
            'role': data.get('role', ''),
            'updatedAt': datetime.now()  # 업데이트 날짜
        }

        # 비밀번호가 제공된 경우 해시 처리
        if 'password' in data:
            hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
            update_fields['password'] = Binary(hashed)

        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_fields}
        )

        if result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'User not found or no changes made'}), 404
        
        return jsonify({'status': 'success', 'message': 'User updated'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getUser/<user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # 사용자 정보를 가공하여 반환할 데이터 형식으로 변환
        user['_id'] = str(user['_id'])  # ObjectId를 문자열로 변환
        user_data = {
            '_id': user['_id'],
            'ID': user.get('ID', ''),
            'name': user.get('name', ''),
            'hire_date': user.get('hire_date', ''),
            'position': user.get('position', ''),
            'role': user.get('role', ''),
            'createdAt': user.get('createdAt', '').isoformat() if user.get('createdAt') else '',
            'updatedAt': user.get('updatedAt', '').isoformat() if user.get('updatedAt') else '',
        }

        return jsonify({'status': 'success', 'data': user_data})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/deleteUser/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    try:
        result = users_collection.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        return jsonify({'status': 'success', 'message': 'User deleted'})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

@app.route('/searchUser', methods=['GET'])
@login_required
def search_user():
    search_query = request.args.get('query', '').strip()
    if not search_query:
        return jsonify({'status': 'error', 'message': 'Query parameter is required'}), 400

    users = list(users_collection.find({
        '$or': [
            {'ID': {'$regex': search_query, '$options': 'i'}},  # 사용자 ID 검색
            {'name': {'$regex': search_query, '$options': 'i'}}  # 사용자 이름 검색
        ]
    }, {'_id': 1, 'ID': 1, 'name': 1}))  # 필요한 필드만 반환

    for user in users:
        user['_id'] = str(user['_id'])  # ObjectId를 문자열로 변환

    return jsonify({'status': 'success', 'data': users})

# Company Routes
@app.route('/addCompany', methods=['POST'])
@login_required
def add_company():
    try:
        data = request.json
        company = {
            'companyName': data['companyName'],
            'companyEnName': data.get('companyEnName', ''),
            'country': data['country'],
            'sector': data['sector'],
            'reg_no': data['reg_no'],
            'type': data['type'],
            'summary': data.get('summary', ''),
            'createdAt': datetime.now(),
            'updatedAt': datetime.now()
        }
        companies_collection.insert_one(company)
        return jsonify({'status': 'success', 'message': 'Company added'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/searchCompany', methods=['GET'])
@login_required
def search_company():
    search_query = request.args.get('query', '').strip()
    if not search_query:
        return jsonify({'status': 'error', 'message': 'Query parameter is required'}), 400

    companies = list(companies_collection.find({
        '$or': [
            {'companyName': {'$regex': search_query, '$options': 'i'}},
            {'companyEnName': {'$regex': search_query, '$options': 'i'}}
        ]
    }, {'_id': 1, 'companyName': 1}))

    for company in companies:
        company['_id'] = str(company['_id']) 

    return jsonify({'status': 'success', 'data': companies})

@app.route('/updateCompany/<company_id>', methods=['PUT'])
@login_required
def update_company(company_id):
    try:
        data = request.json

        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # MongoDB에서 회사 정보 업데이트
        result = companies_collection.update_one(
            {'_id': ObjectId(company_id)},
            {'$set': data, '$currentDate': {'updatedAt': True}}
        )
        
        if result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'Company not found'}), 404
        
        return jsonify({'status': 'success', 'message': 'Company updated successfully'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Company Routes
@app.route('/getCompany/<company_id>', methods=['GET'])
@login_required
def get_company(company_id):
    try:
        company = companies_collection.find_one({'_id': ObjectId(company_id)})
        if not company:
            return jsonify({'status': 'error', 'message': 'Company not found'}), 404
        company['_id'] = str(company['_id'])  # ObjectId를 문자열로 변환
        return jsonify({'status': 'success', 'data': company})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400


@app.route('/getCompanies', methods=['GET'])
@login_required
def get_companies():
    if not check_access_level('companies', session['user_id']):
        return jsonify({'status': 'error', 'data': 'no authority'}), 403
    
    try:
        companies = list(companies_collection.find({}, {'_id': 1, 'companyName': 1, 'companyEnName': 1, 'country': 1, 'sector': 1}))
        
        # ObjectId를 문자열로 변환하고 빈 문자열 처리
        for company in companies:
            company['_id'] = str(company['_id'])
            company['companyName'] = company.get('companyName', '') or ''  # 값이 없으면 빈 문자열
            company['companyEnName'] = company.get('companyEnName', '') or ''  # 값이 없으면 빈 문자열
            company['country'] = company.get('country', '') or ''  # 값이 없으면 빈 문자열
            company['sector'] = company.get('sector', '') or ''  # 값이 없으면 빈 문자열
        
        return jsonify({'status': 'success', 'data': companies})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/deleteCompany/<company_id>', methods=['DELETE'])
@login_required
def delete_company(company_id):
    try:
        result = companies_collection.delete_one({'_id': ObjectId(company_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Company not found'}), 404
        return jsonify({'status': 'success', 'message': 'Company deleted'})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

# Transaction Routes
@app.route('/addInvestment', methods=['POST'])
@login_required
def add_investment():
    try:
        data = request.json
        
        # 데이터에서 필요한 필드 추출
        transaction = {
            'fund_id': data['fund_id'],
            'counterparty_id': data['counterparty_id'],
            'target_id': data['target_id'],
            'trs_type': data['trs_type'],
            'security_type': data['security_type'],
            'currency': data['currency'],
            'prevalue': data['prevalue'],
            'offering': data['offering'],
            'amount': float(data['amount']),  # 금액을 float으로 변환
            'trs_date': datetime.strptime(data['trs_date'], '%Y-%m-%d'),  # 날짜 형식 변환
            'notes': data.get('notes', ''), 
            'terms': data.get('terms', {}), 
            'contributors': data.get('contributors', []),
            'createdBy': session['user_id'],
            'createdAt': datetime.now(),
            'updatedAt': datetime.now()
        }
        
        investments_collection.insert_one(transaction)
        return jsonify({'status': 'success', 'message': 'Transaction added'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/updateInvestment', methods=['PUT'])
@login_required
def update_investment():
    try:
        data = request.json
        updates = {}

        # 클라이언트에서 보내는 데이터에 맞춰 업데이트
        if '_id' in data:
            updates['_id'] = ObjectId(data['_id'])  # 필요에 따라 사용
        if 'fund_id' in data:
            updates['fund_id'] = data['fund_id']
        if 'counterparty_id' in data:
            updates['counterparty_id'] = data['counterparty_id']
        if 'target_id' in data:
            updates['target_id'] = data['target_id']
        if 'trs_type' in data:
            updates['trs_type'] = data['trs_type']
        if 'security_type' in data:
            updates['security_type'] = data['security_type']
        if 'currency' in data:
            updates['currency'] = data['currency']
        if 'offering' in data:
            updates['offering'] = data['offering']
        if 'prevalue' in data:
            updates['prevalue'] = data['prevalue']
        if 'amount' in data:
            updates['amount'] = float(data['amount'])  # 금액은 float으로 변환
        if 'trs_date' in data:
            updates['trs_date'] = datetime.strptime(data['trs_date'], '%Y-%m-%d')
        if 'notes' in data:
            updates['notes'] = data['notes']
        if 'terms' in data:
            updates['terms'] = data['terms']
        if 'contributors' in data:
            updates['contributors'] = data['contributors']
        if 'transactions' in data:
            updates['transactions'] = data['transactions']

        updates['updatedAt'] = datetime.now()
        result = investments_collection.update_one(
            {'_id': ObjectId(data['_id'])},
            {'$set': updates}
        )
        if result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'Transaction not found'}), 404
        return jsonify({'status': 'success', 'message': 'Transaction updated'})
    except (InvalidId, ValueError) as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    
@app.route('/getInvestmentsByUser/<user_id>', methods=['GET'])
@login_required
def get_investments_by_user(user_id):
    try:
        investments = list(investments_collection.find({'contributors': {'$elemMatch': {'userId': user_id}}}))
        for investment in investments:
            investment['_id'] = str(investment['_id']) 
            target_id = investment.get('target_id')
            if target_id:
                company = companies_collection.find_one({'_id': ObjectId(target_id)})
                if company:
                    investment['target'] = company.get('companyName', 'No target') 
            cash_flows = []  
            cash_flows.append({'date': investment['trs_date'].strftime('%Y-%m-%d'), 'amount': -float(investment['amount'])})  

            if 'transactions' in investment:
                for transaction in investment['transactions']:
                    if transaction['transaction_type'] in ['sell', 'redeem', 'interest', 'dividend', 'capReduct']:
                        transaction_date = transaction['date'] if isinstance(transaction['date'], str) else transaction['date'].strftime('%Y-%m-%d')
                        cash_flows.append({'date': transaction_date, 'amount': float(transaction['amount'])})  
            
                    
        return jsonify({'status': 'success', 'data': investments})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

@app.route('/getInvestmentsByFund/<fund_id>', methods=['GET'])
@login_required
def get_investments_by_fund(fund_id):
    try:

        investments = list(investments_collection.find({'fund_id': fund_id}))
        
        for investment in investments:
            investment['_id'] = str(investment['_id'])
            if 'target_id' in investment:
                company = companies_collection.find_one({'_id': ObjectId(investment['target_id'])})
                investment['target'] = company['companyName'] if company else 'Unknown'

        return jsonify({'status': 'success', 'data': investments})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getInvestment/<investment_id>', methods=['GET'])
@login_required
def get_investment(investment_id):
    try:
        transaction = investments_collection.find_one({'_id': ObjectId(investment_id)})
        if not transaction:
            return jsonify({'status': 'error', 'message': 'Transaction not found'}), 404
        transaction['_id'] = str(transaction['_id']) 
        counterparty = companies_collection.find_one({'_id': ObjectId(transaction['counterparty_id'])})
        transaction['counterparty'] = counterparty['companyName'] if counterparty else 'Unknown'
        target_company = companies_collection.find_one({'_id': ObjectId(transaction['target_id'])})
        transaction['target'] = target_company['companyName'] if target_company else 'Unknown'
        fund = funds_collection.find_one({'_id': ObjectId(transaction['fund_id'])})
        transaction['fundName'] = fund['fundName'] if fund else 'Unknown'
        return jsonify({'status': 'success', 'data': transaction})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

@app.route('/getInvestments', methods=['GET'])
@login_required
def get_investments():
    if not check_access_level('investments', session['user_id']):
        return jsonify({'status': 'error', 'data': 'no authority'}), 403

    try:
        investments = list(investments_collection.find())
    except Exception as e:
        return jsonify({'status': 'error', 'data': str(e)}), 500  # 데이터베이스 오류 처리

    for investment in investments:
        investment['_id'] = str(investment['_id'])
        
        try:
            target_company = companies_collection.find_one({'_id': ObjectId(investment['target_id'])})
            investment['target'] = target_company['companyName'] if target_company else 'Unknown'
        except Exception as e:
            investment['target'] = 'No Target'  
        
        try:
            fund = funds_collection.find_one({'_id': ObjectId(investment['fund_id'])})
            investment['fundName'] = fund['fundName'] if fund else 'Unknown'
        except Exception as e:
            investment['fundName'] = 'No Fund' 
    
    return jsonify({'status': 'success', 'data': investments})

@app.route('/deleteInvestment/<investment_id>', methods=['DELETE'])
@login_required
def delete_investment(investment_id):
    try:
        result = investments_collection.delete_one({'_id': ObjectId(investment_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Transaction not found'}), 404
        return jsonify({'status': 'success', 'message': 'Transaction deleted'})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

@app.route('/addFund', methods=['POST'])
@login_required
def add_fund():
    try:
        data = request.json
        
        # 데이터 유효성 검사
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # MongoDB에 펀드 정보 추가
        new_fund = {
            'fundName': data.get('fundName', ''),
            'country': data.get('country', ''),
            'currency': data.get('currency', ''),
            'unit': data.get('unit', ''),
            'totalComAmt': data.get('totalComAmt', ''),
            'GP_commit': data.get('GP_commit', ''),
            'mgt_fee': data.get('mgt_fee', ''),
            'IRR': data.get('IRR', ''),
            'carry': data.get('carry', ''),
            'drawdown': data.get('drawdown', ''),
            'leader': data.get('leader', ''),
            'establish': data.get('establish', ''),
            'notes': data.get('notes', ''),
        }

        # MongoDB에 새 펀드 추가
        funds_collection.insert_one(new_fund)

        return jsonify({'status': 'success', 'message': 'Fund added successfully!'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/deleteFund/<fund_id>', methods=['DELETE'])
@login_required
def delete_fund(fund_id):
    try:
        result = funds_collection.delete_one({'_id': ObjectId(fund_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Fund not found'}), 404
        return jsonify({'status': 'success', 'message': 'Fund deleted'})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

@app.route('/updateFund/<fund_id>', methods=['PUT'])
@login_required
def update_fund(fund_id):
    try:
        data = request.json
        
        # 데이터 유효성 검사
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # MongoDB에서 펀드 정보 업데이트
        update_result = funds_collection.update_one(
            {'_id': ObjectId(fund_id)},
            {'$set': {
                'fundName': data.get('fundName', ''),
                'country': data.get('country', ''),
                'currency': data.get('currency', ''),
                'unit': data.get('unit', ''),
                'totalComAmt': data.get('totalComAmt', ''),
                'GP_commit': data.get('GP_commit', ''),
                'mgt_fee': data.get('mgt_fee', ''),
                'expIRR': data.get('expIRR', ''),
                'IRR': data.get('IRR', ''),
                'carry': data.get('carry', ''),
                'drawdown': data.get('drawdown', ''),
                'leader': data.get('leader', ''),
                'establish': data.get('establish', ''),
                'notes': data.get('notes', ''),
            }}
        )

        if update_result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'Fund not found or no changes made'}), 404
        
        return jsonify({'status': 'success', 'message': 'Fund updated successfully!'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/getFund/<fund_id>', methods=['GET'])
@login_required
def get_fund(fund_id):
    try:
        fund = funds_collection.find_one({'_id': ObjectId(fund_id)})
        if not fund:
            return jsonify({'status': 'error', 'message': 'Fund not found'}), 404
        fund['_id'] = str(fund['_id'])
        user = users_collection.find_one({'_id': ObjectId(fund['leader'])})
        fund['leaderName'] = user['name'] if user else ''
        return jsonify({'status': 'success', 'data': fund})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

@app.route('/getFunds', methods=['GET'])
@login_required
def get_funds():
    if not check_access_level('funds', session['user_id']):
        return jsonify({'status': 'error', 'data': 'no authority'}), 403
    
    funds = list(funds_collection.find())
    for fund in funds:
        fund['_id'] = str(fund['_id'])
        fund['fundName'] = fund.get('fundName', '') or ''
        fund['country'] = fund.get('country', '') or ''
        fund['unit'] = fund.get('unit', '') or ''
        fund['currency'] = fund.get('currency', '') or ''
        fund['totalComAmt'] = fund.get('totalComAmt', '') or ''
        fund['GP_commit'] = fund.get('GP_commit', '') or ''
        fund['mgt_fee'] = fund.get('mgt_fee', '') or ''
        fund['drawdown'] = fund.get('drawdown', '') or ''
        fund['notes'] = fund.get('notes', '') or ''
        fund['leader'] = fund.get('leader', '') or ''
        fund['establish'] = fund.get('establish', '') or ''
        fund['IRR'] = fund.get('IRR', '') or ''
        fund['carry'] = fund.get('carry', '') or ''

    return jsonify({'status': 'success', 'data': funds})

@app.route('/getFundsByUser/<user_id>', methods=['GET'])
@login_required
def get_funds_by_user(user_id):

    funds = list(funds_collection.find({'leader': user_id}))
    for fund in funds:
        fund['_id'] = str(fund['_id']) 
        fund['fundName'] = fund.get('fundName', '') or ''
        fund['country'] = fund.get('country', '') or ''
        fund['unit'] = fund.get('unit', '') or ''
        fund['currency'] = fund.get('currency', '') or ''
        fund['totalComAmt'] = fund.get('totalComAmt', '') or ''
        fund['leader'] = fund.get('leader', '') or ''
        fund['IRR'] = fund.get('IRR', '') or ''

    return jsonify({'status': 'success', 'data': funds})

@app.route('/searchFund', methods=['GET'])
@login_required
def search_fund():
    search_query = request.args.get('query', '').strip()
    if not search_query:
        return jsonify({'status': 'error', 'message': 'Query parameter is required'}), 400

    funds = list(funds_collection.find({
        'fundName': {'$regex': search_query, '$options': 'i'}
    }, {'_id': 1, 'fundName': 1, 'currency': 1}))

    for fund in funds:
        fund['_id'] = str(fund['_id']) 

    return jsonify({'status': 'success', 'data': funds})

@app.route('/getSecurities', methods=['GET'])
@login_required
def get_securities():
    if not check_access_level('securities', session['user_id']):
        return jsonify({'status': 'error', 'data': 'no authority'}), 403
    
    try:
        securities = list(securities_collection.find())  # 모든 보안 데이터 가져오기
        for security in securities:
            security['_id'] = str(security['_id'])  # ObjectId를 문자열로 변환
        return jsonify({'status': 'success', 'data': securities})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getSecurity/<security_id>', methods=['GET'])
@login_required
def get_security(security_id):
    try:
        # security_id에 해당하는 보안 정보를 찾습니다.
        security = securities_collection.find_one({'_id': ObjectId(security_id)})
        
        if security:
            security['_id'] = str(security['_id'])  # ObjectId를 문자열로 변환
            return jsonify({'status': 'success', 'data': security})
        else:
            return jsonify({'status': 'error', 'message': 'Security not found'}), 404
            
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/addSecurity', methods=['POST'])
@login_required
def add_security():
    try:
        data = request.json
        
        # 데이터 유효성 검사
        if not data or 'type' not in data or 'trs_type' not in data:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        # 보안 데이터 생성
        security = {
            'type': data['type'],
            'trs_type': data['trs_type'],
            'terms': data.get('terms', {}),  # terms는 선택적
            'createdAt': datetime.now(),
            'updatedAt': datetime.now()
        }

        # MongoDB에 보안 정보 추가
        securities_collection.insert_one(security)

        return jsonify({'status': 'success', 'message': 'Security added successfully!'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/updateSecurity/<security_id>', methods=['PUT'])
@login_required
def update_security(security_id):
    try:
        data = request.json
        
        # 데이터 유효성 검사
        if not data or 'type' not in data or 'trs_type' not in data:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        # 업데이트할 데이터 생성
        update_fields = {
            'type': data['type'],
            'trs_type': data['trs_type'],
            'terms': data.get('terms', {}),  # terms는 선택적
            'updatedAt': datetime.now()  # 업데이트 날짜
        }

        # MongoDB에서 보안 정보 업데이트
        result = securities_collection.update_one(
            {'_id': ObjectId(security_id)},
            {'$set': update_fields}
        )

        if result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'Security not found or no changes made'}), 404
        
        return jsonify({'status': 'success', 'message': 'Security updated successfully!'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/deleteSecurity/<security_id>', methods=['DELETE'])
@login_required
def delete_security(security_id):
    try:
        result = securities_collection.delete_one({'_id': ObjectId(security_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Security not found'}), 404
        return jsonify({'status': 'success', 'message': 'Security deleted successfully!'})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getAuthCollects', methods=['GET'])
@login_required
def get_auth_collects():
    if not check_access_level('auth_collects', session['user_id']):
        return jsonify({'status': 'error', 'data': 'no authority'}), 403
    
    try:
        auth_collects = list(auth_access_collection.find())
        for auth in auth_collects:
            auth['_id'] = str(auth['_id'])  # ObjectId를 문자열로 변환
        return jsonify({'status': 'success', 'data': auth_collects})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getAuthCollect/<auth_id>', methods=['GET'])
@login_required
def get_auth_collect(auth_id):
    try:
        auth_collect = auth_access_collection.find_one({'_id': ObjectId(auth_id)})
        if not auth_collect:
            return jsonify({'status': 'error', 'message': 'Auth collect not found'}), 404
        auth_collect['_id'] = str(auth_collect['_id'])  # ObjectId를 문자열로 변환
        return jsonify({'status': 'success', 'data': auth_collect})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/addAuthCollect', methods=['POST'])
@login_required
def add_auth_collect():
    try:
        data = request.json
        if not data or 'collection' not in data or 'access_level' not in data:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        auth_collect = {
            'collection': data['collection'],
            'access_level': data['access_level'],
            'createdAt': datetime.now(),
            'updatedAt': datetime.now()
        }
        
        auth_access_collection.insert_one(auth_collect)
        return jsonify({'status': 'success', 'message': 'Auth collect added successfully!'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/updateAuthCollect/<auth_id>', methods=['PUT'])
@login_required
def update_auth_collect(auth_id):
    try:
        data = request.json
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        update_fields = {
            'collection': data.get('collection', ''),
            'access_level': data.get('access_level', ''),
            'updatedAt': datetime.now()
        }

        result = auth_access_collection.update_one(
            {'_id': ObjectId(auth_id)},
            {'$set': update_fields}
        )

        if result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'Auth collect not found or no changes made'}), 404
        
        return jsonify({'status': 'success', 'message': 'Auth collect updated successfully!'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/deleteAuthCollect/<auth_id>', methods=['DELETE'])
@login_required
def delete_auth_collect(auth_id):
    try:
        result = auth_access_collection.delete_one({'_id': ObjectId(auth_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Auth collect not found'}), 404
        return jsonify({'status': 'success', 'message': 'Auth collect deleted successfully!'})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
# Contributions Routes
@app.route('/getContributions', methods=['GET'])
@login_required
def get_contributions():
    try:
        contributions = list(contributions_collection.find())
        for contribution in contributions:
            contribution['_id'] = str(contribution['_id'])  # ObjectId를 문자열로 변환
            
            # trans_id를 사용하여 investments_collection에서 trans_name 찾기
            transaction = investments_collection.find_one({'_id': ObjectId(contribution['trans_id'])})
            contribution['target_id'] = transaction['target_id'] if transaction else 'Unknown' 
            contribution['security_type'] = transaction['security_type'] if transaction else 'Unknown'
            contribution['fund_id'] = transaction['fund_id'] if transaction else 'Unknown'

            # target_id를 사용하여 companies_collection에서 회사명 찾기
            if transaction and transaction['target_id']:
                company = companies_collection.find_one({'_id': ObjectId(transaction['target_id'])})
                contribution['target'] = company['companyName'] if company else 'Unknown'  # 회사명 추가
            else:
                contribution['target'] = 'Unknown'

            # fund_id를 사용하여 funds_collection에서 펀드명 찾기
            if transaction and transaction.get('fund_id'):
                fund = funds_collection.find_one({'_id': ObjectId(transaction['fund_id'])})
                contribution['fund'] = fund['fundName'] if fund else 'Unknown'  # 펀드명 추가
            else:
                contribution['fund'] = 'Unknown'

        return jsonify({'status': 'success', 'data': contributions})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getContribution/<contribution_id>', methods=['GET'])
@login_required
def get_contribution(contribution_id):
    try:
        contribution = contributions_collection.find_one({'_id': ObjectId(contribution_id)})
        if not contribution:
            return jsonify({'status': 'error', 'message': 'Contribution not found'}), 404
        contribution['_id'] = str(contribution['_id'])  # ObjectId를 문자열로 변환
        return jsonify({'status': 'success', 'data': contribution})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/deleteContribution/<contribution_id>', methods=['DELETE'])
@login_required
def delete_contribution(contribution_id):
    try:
        result = contributions_collection.delete_one({'_id': ObjectId(contribution_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Contribution not found'}), 404
        return jsonify({'status': 'success', 'message': 'Contribution deleted'})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/updateContribution/<contribution_id>', methods=['PUT'])
@login_required
def update_contribution(contribution_id):
    try:
        data = request.json
        update_fields = {
            'trans_id': data.get('trans_id', ''),
            'table': data.get('table', ''),
            # 필요한 다른 필드 추가
            'updatedAt': datetime.now()  # 업데이트 날짜
        }

        result = contributions_collection.update_one(
            {'_id': ObjectId(contribution_id)},
            {'$set': update_fields}
        )

        if result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'Contribution not found or no changes made'}), 404
        
        return jsonify({'status': 'success', 'message': 'Contribution updated successfully'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/addContribution', methods=['POST'])
@login_required
def add_contribution():
    try:
        data = request.json
        contribution = {
            'trans_id': data['trans_id'],
            'table': data['table'],
            # 필요한 다른 필드 추가
            'createdAt': datetime.now(),
            'updatedAt': datetime.now()
        }

        contributions_collection.insert_one(contribution)
        return jsonify({'status': 'success', 'message': 'Contribution added successfully!'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

def check_access_level(collection, user_id):
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if user:
        role = user.get('role')
        user_access = next((item for item in AccessLevel if item['role'] == role), None)
        access_level = auth_access_collection.find_one({'collection': collection})
        collection_access = next((item for item in AccessLevel if item['role'] == access_level['access_level']), None)
        if user_access and collection_access:
            return user_access['score'] <= collection_access['score']
    
    return False



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=PM_port)  # 모든 IP에서 접근 가능