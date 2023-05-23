package com.pki.example.repo;

import com.pki.example.model.MagicLink;
import com.pki.example.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MagicLinkRepository extends JpaRepository<MagicLink,Integer> {
    MagicLink findOneByLinkId(long id);
}
