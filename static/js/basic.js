$(document).ready(function() {
    let profileId = getUserId();
    let profileInfo = {};
    if (!profileId) {
        alert('Sign-in required.');
        window.location.href ="/signin";
        return;
    } 

    $.ajax({
        url: `/getUser/${profileId}`,
        method: 'GET',
        success: function(response) {
            console.log(response);
            profileInfo = response.data;
            ProfileModal();
            profileDataMapping(profileInfo);
        },
        error: function() {
            alert('Failed to load transaction details');
        }
    });

    $('#signOutBtn').click(function(event) {
        event.preventDefault(); // 기본 링크 동작 방지

        $.ajax({
            url: '/signout', // 로그아웃 요청 URL
            type: 'POST', // POST 메서드 사용
            success: function(response) {
                if (response.status === 'success') {
                    alert('Logged out successfully!'); // 성공 메시지
                    window.location.href = '/'; // 페이지 새로 고침
                } else {
                    alert('Error logging out: ' + response.message); // 에러 메시지
                }
            },
            error: function(xhr, status, error) {
                alert('An error occurred: ' + error); // AJAX 요청 에러 처리
            }
        });
    });

    $('#myProfileBtn').click(function(event) {
        event.preventDefault();

        ProfileModal();
        profileDataMapping(profileInfo);

        $('#ProfileModal').modal('show');

        $('#ProfileModal').on('hidden.bs.modal', function () {
            $(this).remove(); // 모달 제거
        });
    });

    function ProfileModal() {
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
                                    <input type="text" class="form-control" id="profile_position" placeholder="Enter position" required>
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
        $('body').append(modalHtml);
    };

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

    function getUserId() {
        const userId = localStorage.getItem('portfolio_user_id');
        const expirationTime = localStorage.getItem('portfolio_user_id_expiration');
    
        // 만료 시간이 설정되어 있고, 현재 시간이 만료 시간보다 크면
        if (expirationTime && Date.now() > expirationTime) {
            // 만료된 경우 localStorage에서 삭제
            localStorage.removeItem('portfolio_user_id');
            localStorage.removeItem('portfolio_user_id_expiration');
            return null; // 만료된 경우 null 반환
        }
    
        return userId; // 만료되지 않은 경우 사용자 ID 반환
    }
    
});