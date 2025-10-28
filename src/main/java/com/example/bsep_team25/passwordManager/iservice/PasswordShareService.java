package com.example.bsep_team25.passwordManager.iservice;

import com.example.bsep_team25.passwordManager.dto.SharePasswordRequest;
import com.example.bsep_team25.passwordManager.dto.SharePasswordResponse;

import java.util.List;

public interface PasswordShareService {
    SharePasswordResponse share(SharePasswordRequest req);
    List<SharePasswordResponse> listReceived();
    List<SharePasswordResponse> listSent();
    void delete(Long shareId);
    SharePasswordResponse getReceivedDetail(Long shareId);
}
