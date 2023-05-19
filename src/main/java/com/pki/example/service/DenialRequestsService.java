package com.pki.example.service;

import com.pki.example.model.DenialRequests;
import com.pki.example.repo.DenialRequestsRepository;
import org.springframework.data.domain.Example;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DenialRequestsService {
    public DenialRequestsRepository denialRequestsRepository;

    <S extends DenialRequests> Optional<S> findOne(Example<S> example){
        return findOne(example);
    }
}
