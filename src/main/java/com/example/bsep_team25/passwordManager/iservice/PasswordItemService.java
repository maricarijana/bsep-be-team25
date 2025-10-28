package com.example.bsep_team25.passwordManager.iservice;

import com.example.bsep_team25.passwordManager.dto.CreatePasswordItemRequest;
import com.example.bsep_team25.passwordManager.dto.PasswordItemResponse;

import java.util.List;

public interface PasswordItemService {
    PasswordItemResponse create(CreatePasswordItemRequest req);
    List<PasswordItemResponse> listMine();
    void delete(Long itemId);
    PasswordItemResponse getDetail(Long itemId);
}
