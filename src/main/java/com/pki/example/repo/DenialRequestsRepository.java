package com.pki.example.repo;

import com.pki.example.model.DenialRequests;
import org.springframework.data.domain.Example;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DenialRequestsRepository extends JpaRepository<DenialRequests,Integer> {
    @Override
    <S extends DenialRequests> Optional<S> findOne(Example<S> example);
    DenialRequests findOneByEmail(String email);
}
