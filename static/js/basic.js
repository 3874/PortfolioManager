$(document).ready(function() {

    $('#signOutBtn').click(function(event) {
        event.preventDefault();
        SignOut();
    });

    $('#myProfileBtn').click(function(event) {
        $('#ProfileModal').modal('show');
    });

    $('body').on('click', '#saveProfileBtn', function(event) {
        event.preventDefault();
        const userId = $('#profileId').val();
        const userData = {
          name: $('#profile_name').val(), // 사용자 이름
          hire_date: $('#profile_hire_date').val(), // 고용 날짜
          position: $('#profile_position').val(), // 직위
          role: $('#profile_role').val(), // 역할
        };
        // AJAX 요청으로 데이터 전송
        $.ajax({
            url: `/updateUser/${userId}`, // 회사 ID를 URL에 포함
            type: 'PUT', // PUT 메서드 사용
            contentType: 'application/json',
            data: JSON.stringify(userData),
            success: function(response) {
                if (response.status === 'success') {
                    alert('Company updated successfully!');
                    window.location.reload();
                } else {
                    alert('Error updating company: ' + response.message);
                }
            },
            error: function(xhr, status, error) {
                alert('An error occurred: ' + error);
            }
        });
    });
  
});

function SignOut(){

    $.ajax({
        url: '/signout', // 로그아웃 요청 URL
        type: 'POST', // POST 메서드 사용
        success: function(response) {
            if (response.status === 'success') {
                localStorage.removeItem('portfolio_user_id');
                localStorage.removeItem('portfolio_user_id_expiration');
                alert('Logged out successfully!');
                window.location.href = '/signin'; 
            } else {
                alert('Error logging out: ' + response.message); 
                window.location.href = '/signin';
            }
        },
        error: function(xhr, status, error) {
            alert('An error occurred: ' + error);
        }
    });
}

function ProfileModal() {

    $('#ProfileModal').remove();
    
    const modalHtml = `
        <div class="modal fade" tabindex="-1" id="ProfileModal" role="dialog" aria-labelledby="ProfileModalLabel">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                        <h4 class="modal-title" id="addUserBtn">Update My Profile</h4>
                    </div>
                    <div class="modal-body">
                        <form id="UserForm">
                            <div class="form-group">
                                <label for="profile_ID">User ID</label>
                                <input type="text" class="form-control" id="profile_ID" placeholder="Enter user ID" readonly>
                            </div>
                            <div class="form-group">
                                <label for="profile_name">Name</label>
                                <input type="text" class="form-control" id="profile_name" placeholder="Enter name" required>
                            </div>
                            <div class="form-group">
                                <label for="profile_hire_date">Hire Date</label>
                                <input type="date" class="form-control" id="profile_hire_date" required>
                            </div>
                            <div class="form-group">
                                <label for="profile_position">Position</label>
                                <input type="text" class="form-control" id="profile_position" readonly>
                            </div>
                            <div class="form-group">
                                <label for="profile_role">Role</label>
                                <input type="text" class="form-control" id="profile_role" readonly>
                            </div>
                            <input type="hidden" id="profileId" value="">
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" id="saveProfileBtn">Save</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // 모달 HTML 추가
    $('body').append(modalHtml);
    
    // 모달 초기화
    $('#ProfileModal').modal({
        backdrop: 'static',
        keyboard: false,
        show: false
    });
};

$(document).ready(function() {
    // myProfileBtn 클릭 이벤트를 ProfileModal 초기화 이후에 바인딩
    $('#myProfileBtn').off('click').on('click', function(event) {
        event.preventDefault();
        try {
            $('#ProfileModal').modal('show');
        } catch (error) {
            console.error('Modal error:', error);
            // 모달이 없으면 다시 초기화
            ProfileModal();
            $('#ProfileModal').modal('show');
        }
    });
});

function profileDataMapping(info) {
    $('#profileId').val(info._id); 
    $('#profile_ID').val(info.ID); 
    $('#profile_name').val(info.name); // 사용자 이름
    $('#profile_hire_date').val(info.hire_date); // 고용 날짜
    $('#profile_position').val(info.position); // 직위
    $('#profile_role').val(info.role); // 역할
    // profile 
    $('#profilename1').text(info.name); 
    $('#profilename2').text(info.name); 
    $('#profilename3').text(info.name); 
    $('#profilerole').text(info.role);
    $('#profiledate').text(info.createdAt.substring(0, 10));  

}

async function getUser(userId, sessionToken) {
    try {
        const response = await $.ajax({
            url: `/getUser/${userId}`,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + sessionToken
            },
        });

        if (response.status === 'success') {
            return {'status': 'success', 'data': response.data};
        } else {
            // 응답이 성공적이지 않은 경우
            return {'status': 'error', 'message': response.message || 'Failed to retrieve user data.'};
        }
    } catch (error) {
        // AJAX 요청이 실패한 경우
        return {'status': 'error', 'message': error.statusText || 'An error occurred while fetching user data.'};
    }
}

function getSessionFromMemory() {
    const JSON_session = localStorage.getItem('portfoliomanager_session');

    if (!JSON_session) {
        window.location.href = '/signin';
        return;
    }
    const session = JSON.parse(JSON_session);

    userId = session['user_id'];
    sessionToken = session['session_token'];
    created_at = session['created_at'];

    if (!userId || !sessionToken || !created_at) {
        localStorage.setItem('fileflicker_session', '');
        window.location.href = '/signin';
    }

    const createdAtDate = new Date(created_at);
    const currentTime = new Date();

    const LimitHour = 1; // Hour (서버에서도 바꿔야 함)
    const LimitTime = LimitHour * 60 * 60 * 1000; // 밀리초로 변환

    if ((currentTime.getTime() - createdAtDate.getTime()) > LimitTime) {
        localStorage.setItem('fileflicker_session', '');
        window.location.href = '/signin';
        return; 
    }

    return session; 
}