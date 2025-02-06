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
# Auth Routes
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
@app.route('/addTransaction', methods=['POST'])
@login_required
def add_transaction():
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
            'unit': data['unit'],
            'prevalue': data['prevalue'],
            'amount': float(data['amount']),  # 금액을 float으로 변환
            'trs_date': datetime.strptime(data['trs_date'], '%Y-%m-%d'),  # 날짜 형식 변환
            'notes': data.get('notes', ''),  # notes는 선택적
            'terms': data.get('terms', {}),  # terms는 선택적
            'createdBy': session['user_id'],
            'createdAt': datetime.now(),
            'updatedAt': datetime.now()
        }
        
        # 트랜잭션 추가
        transactions_collection.insert_one(transaction)
        return jsonify({'status': 'success', 'message': 'Transaction added'})
    
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/updateTransaction', methods=['PUT'])
@login_required
def update_transaction():
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
        if 'prevalue' in data:
            updates['prevalue'] = data['prevalue']
        if 'unit' in data:
            updates['unit'] = data['unit']
        if 'amount' in data:
            updates['amount'] = float(data['amount'])  # 금액은 float으로 변환
        if 'trs_date' in data:
            updates['trs_date'] = datetime.strptime(data['trs_date'], '%Y-%m-%d')
        if 'notes' in data:
            updates['notes'] = data['notes']
        if 'terms' in data:
            updates['terms'] = data['terms']  # terms 업데이트

        updates['updatedAt'] = datetime.now()
        result = transactions_collection.update_one(
            {'_id': ObjectId(data['_id'])},
            {'$set': updates}
        )
        if result.modified_count == 0:
            return jsonify({'status': 'error', 'message': 'Transaction not found'}), 404
        return jsonify({'status': 'success', 'message': 'Transaction updated'})
    except (InvalidId, ValueError) as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    
@app.route('/getTransactionByUser/<user_id>', methods=['GET'])
@login_required
def get_transaction_by_user(user_id):
    try:
        # fund_id에 해당하는 모든 트랜잭션을 조회합니다.
        transactions = list(transactions_collection.find({'user_id': user_id}))

        # target_id별로 트랜잭션을 그룹핑할 딕셔너리 생성
        grouped_transactions = {}

        for transaction in transactions:
            # ObjectId를 문자열로 변환
            transaction['_id'] = str(transaction['_id'])

            # 만약 trs_date가 문자열이라면 datetime 객체로 변환 (예시)
            if isinstance(transaction.get('trs_date'), str):
                transaction['trs_date'] = datetime.fromisoformat(transaction['trs_date'])

            # target_id에 해당하는 회사 이름 조회
            target_company = companies_collection.find_one({'_id': ObjectId(transaction['target_id'])})
            transaction['target'] = target_company['companyName'] if target_company else 'Unknown'

            # 그룹핑: 동일 target_id의 거래들을 모음
            target_id = transaction['target_id']
            if target_id not in grouped_transactions:
                grouped_transactions[target_id] = {
                    'target': transaction['target'],
                    'target_id': transaction['target_id'],
                    'unit': transaction['unit'],
                    'currency': transaction['currency'],
                    'transactions': [],
                    'total_buy': 0,   # buy한 총금액 초기화
                    'total_sell': 0   # sell한 총금액 초기화
                }
            
            # 트랜잭션을 해당 그룹에 추가
            grouped_transactions[target_id]['transactions'].append(transaction)
            
            # trs_type에 따라 각 그룹의 총금액 갱신
            amount = transaction.get('amount', 0)
            if transaction.get('trs_type', '').lower() == 'buy':
                grouped_transactions[target_id]['total_buy'] += amount
            elif transaction.get('trs_type', '').lower() == 'sell':
                grouped_transactions[target_id]['total_sell'] += amount
            else:
                # 기타 유형의 경우 별도 처리 가능 (현재는 buy로 처리)
                grouped_transactions[target_id]['total_buy'] += amount

        # 각 그룹별로 xirr 함수를 이용해 IRR 계산
        for group in grouped_transactions.values():
            cashflows = []
            # 거래일 기준으로 정렬 (필요시)
            group['transactions'].sort(key=lambda x: x['trs_date'])
            for txn in group['transactions']:
                # trs_type에 따라 현금흐름 부호 결정:
                # 'buy'이면 투자이므로 음수, 'sell'이면 회수이므로 양수로 처리
                amount = txn.get('amount', 0)
                if txn.get('trs_type', '').lower() == 'buy':
                    cashflow = -amount
                elif txn.get('trs_type', '').lower() == 'sell':
                    cashflow = amount
                else:
                    # 기타 유형에 대해서는 기본적으로 음수 처리하거나 별도 로직 추가 가능
                    cashflow = -amount

                cashflows.append((txn['trs_date'], cashflow))

            try:
                # xirr 함수에 cashflows를 전달하여 IRR 계산
                irr_value = xirr(cashflows)
            except Exception as e:
                # IRR 계산이 불가능한 경우 None 처리
                irr_value = None

            # 그룹 정보에 IRR 값 추가 (예: 소수점 4자리까지 표시)
            group['irr'] = round(irr_value, 4) if irr_value is not None else None

        # 최종 결과를 그룹별 리스트로 변환
        result = list(grouped_transactions.values())

        return jsonify({'status': 'success', 'data': result})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getTransactionByFund/<fund_id>', methods=['GET'])
@login_required
def get_transaction_by_fund(fund_id):
    try:
        # fund_id에 해당하는 모든 트랜잭션을 조회합니다.
        transactions = list(transactions_collection.find({'fund_id': fund_id}))

        # target_id별로 트랜잭션을 그룹핑할 딕셔너리 생성
        grouped_transactions = {}

        for transaction in transactions:
            # ObjectId를 문자열로 변환
            transaction['_id'] = str(transaction['_id'])

            # 만약 trs_date가 문자열이라면 datetime 객체로 변환 (예시)
            if isinstance(transaction.get('trs_date'), str):
                transaction['trs_date'] = datetime.fromisoformat(transaction['trs_date'])

            # target_id에 해당하는 회사 이름 조회
            target_company = companies_collection.find_one({'_id': ObjectId(transaction['target_id'])})
            transaction['target'] = target_company['companyName'] if target_company else 'Unknown'

            # 그룹핑: 동일 target_id의 거래들을 모음
            target_id = transaction['target_id']
            if target_id not in grouped_transactions:
                grouped_transactions[target_id] = {
                    'target': transaction['target'],
                    'target_id': transaction['target_id'],
                    'unit': transaction['unit'],
                    'currency': transaction['currency'],
                    'transactions': [],
                    'total_buy': 0,   # buy한 총금액 초기화
                    'total_sell': 0   # sell한 총금액 초기화
                }
            
            # 트랜잭션을 해당 그룹에 추가
            grouped_transactions[target_id]['transactions'].append(transaction)
            
            # trs_type에 따라 각 그룹의 총금액 갱신
            amount = transaction.get('amount', 0)
            if transaction.get('trs_type', '').lower() == 'buy':
                grouped_transactions[target_id]['total_buy'] += amount
            elif transaction.get('trs_type', '').lower() == 'sell':
                grouped_transactions[target_id]['total_sell'] += amount
            else:
                # 기타 유형의 경우 별도 처리 가능 (현재는 buy로 처리)
                grouped_transactions[target_id]['total_buy'] += amount

        # 각 그룹별로 xirr 함수를 이용해 IRR 계산
        for group in grouped_transactions.values():
            cashflows = []
            # 거래일 기준으로 정렬 (필요시)
            group['transactions'].sort(key=lambda x: x['trs_date'])
            for txn in group['transactions']:
                # trs_type에 따라 현금흐름 부호 결정:
                # 'buy'이면 투자이므로 음수, 'sell'이면 회수이므로 양수로 처리
                amount = txn.get('amount', 0)
                if txn.get('trs_type', '').lower() == 'buy':
                    cashflow = -amount
                elif txn.get('trs_type', '').lower() == 'sell':
                    cashflow = amount
                else:
                    # 기타 유형에 대해서는 기본적으로 음수 처리하거나 별도 로직 추가 가능
                    cashflow = -amount

                cashflows.append((txn['trs_date'], cashflow))

            try:
                # xirr 함수에 cashflows를 전달하여 IRR 계산
                irr_value = xirr(cashflows)
            except Exception as e:
                # IRR 계산이 불가능한 경우 None 처리
                irr_value = None

            # 그룹 정보에 IRR 값 추가 (예: 소수점 4자리까지 표시)
            group['irr'] = round(irr_value, 4) if irr_value is not None else None

        # 최종 결과를 그룹별 리스트로 변환
        result = list(grouped_transactions.values())

        return jsonify({'status': 'success', 'data': result})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/getTransaction/<transaction_id>', methods=['GET'])
@login_required
def get_transaction(transaction_id):
    try:
        transaction = transactions_collection.find_one({'_id': ObjectId(transaction_id)})
        if not transaction:
            return jsonify({'status': 'error', 'message': 'Transaction not found'}), 404
        transaction['_id'] = str(transaction['_id']) 
        counterparty = companies_collection.find_one({'_id': ObjectId(transaction['target_id'])})
        transaction['counterparty'] = counterparty['companyName'] if counterparty else 'Unknown'
        target_company = companies_collection.find_one({'_id': ObjectId(transaction['target_id'])})
        transaction['target'] = target_company['companyName'] if target_company else 'Unknown'
        fund = funds_collection.find_one({'_id': ObjectId(transaction['fund_id'])})
        transaction['fundName'] = fund['fundName'] if fund else 'Unknown'
        return jsonify({'status': 'success', 'data': transaction})
    except InvalidId:
        return jsonify({'status': 'error', 'message': 'Invalid ID format'}), 400

@app.route('/getTransactions', methods=['GET'])
@login_required
def get_transactions():
    if not check_access_level('transactions', session['user_id']):
        return jsonify({'status': 'error', 'data': 'no authority'}), 403

    try:
        transactions = list(transactions_collection.find())
    except Exception as e:
        return jsonify({'status': 'error', 'data': str(e)}), 500  # 데이터베이스 오류 처리

    for transaction in transactions:
        transaction['_id'] = str(transaction['_id'])
        
        try:
            target_company = companies_collection.find_one({'_id': ObjectId(transaction['target_id'])})
            transaction['target'] = target_company['companyName'] if target_company else 'Unknown'
        except Exception as e:
            transaction['target'] = 'Error retrieving target'  # 오류 발생 시 기본값 설정
        
        try:
            fund = funds_collection.find_one({'_id': ObjectId(transaction['fund_id'])})
            transaction['fundName'] = fund['fundName'] if fund else 'Unknown'
        except Exception as e:
            transaction['fundName'] = 'Error retrieving fund'  # 오류 발생 시 기본값 설정
    
    return jsonify({'status': 'success', 'data': transactions})

@app.route('/deleteTransaction/<transaction_id>', methods=['DELETE'])
@login_required
def delete_transaction(transaction_id):
    try:
        result = transactions_collection.delete_one({'_id': ObjectId(transaction_id)})
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
        fund['_id'] = str(fund['_id'])  # ObjectId를 문자열로 변환
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
        fund['_id'] = str(fund['_id'])  # ObjectId를 문자열로 변환
        # 각 필드가 없을 경우 빈 문자열로 설정
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

@app.route('/searchFund', methods=['GET'])
@login_required
def search_fund():
    search_query = request.args.get('query', '').strip()
    if not search_query:
        return jsonify({'status': 'error', 'message': 'Query parameter is required'}), 400

    funds = list(funds_collection.find({
        'fundName': {'$regex': search_query, '$options': 'i'}
    }, {'_id': 1, 'fundName': 1}))

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
            
            # trans_id를 사용하여 transactions_collection에서 trans_name 찾기
            transaction = transactions_collection.find_one({'_id': ObjectId(contribution['trans_id'])})
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

def xirr(cashflows=None, dates=None, guess=0.1, tol=1e-6, max_iterations=100):
    
    # 입력 형식에 따라 데이터를 처리
    if cashflows is None:
        raise ValueError("현금흐름 데이터가 제공되어야 합니다.")
    
    # cashflows가 (날짜, 현금흐름) 튜플들의 리스트인 경우
    if dates is None:
        if not isinstance(cashflows, list) or len(cashflows) < 2:
            raise ValueError("최소 두 개 이상의 (날짜, 현금흐름) 튜플이 필요합니다.")
        # 날짜와 현금흐름을 분리하고, 날짜를 기준으로 정렬
        cashflows = sorted(cashflows, key=lambda x: x[0])
        dates = [cf[0] for cf in cashflows]
        amounts = [cf[1] for cf in cashflows]
    else:
        # cashflows와 dates가 각각 리스트 형태로 주어지는 경우
        if len(cashflows) != len(dates):
            raise ValueError("cashflows와 dates의 길이는 동일해야 합니다.")
        if len(cashflows) < 2:
            raise ValueError("최소 두 개 이상의 거래가 필요합니다.")
        # 두 리스트를 날짜 기준으로 정렬
        combined = sorted(zip(dates, cashflows), key=lambda x: x[0])
        dates, amounts = zip(*combined)
        dates = list(dates)
        amounts = list(amounts)
    
    # 투자와 회수가 모두 있는지 확인
    if not (any(amt > 0 for amt in amounts) and any(amt < 0 for amt in amounts)):
        raise ValueError("양의 현금흐름과 음의 현금흐름이 모두 존재해야 IRR을 계산할 수 있습니다.")
    
    # 기준 날짜: 첫 번째 날짜
    t0 = dates[0]
    
    def npv(r):
        total = 0.0
        for amt, dt in zip(amounts, dates):
            t = (dt - t0).days / 365.0
            total += amt / ((1 + r) ** t)
        return total
    
    def npv_derivative(r):
        total = 0.0
        for amt, dt in zip(amounts, dates):
            t = (dt - t0).days / 365.0
            total += -t * amt / ((1 + r) ** (t + 1))
        return total

    # 초기 추정치로 Newton-Raphson 방법 수행
    r = guess
    for i in range(max_iterations):
        f_value = npv(r)
        deriv_value = npv_derivative(r)
        if deriv_value == 0:
            raise ZeroDivisionError("도함수의 값이 0이 되어 수렴할 수 없습니다.")
        new_r = r - f_value / deriv_value
        if abs(new_r - r) < tol:
            return new_r
        r = new_r

    raise RuntimeError("IRR 계산이 최대 반복 횟수 내에 수렴하지 않았습니다.")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=PM_port)  # 모든 IP에서 접근 가능