package com.hyperedu.repository;

import com.hyperedu.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;

/**
 * Created by fan.jin on 2016-10-15.
 */

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername( String username );

    @Modifying
    @Query(value="Insert Into USERS (username,password) Values (:username,:password)", nativeQuery = true)
    @Transactional
    void saveByQuery(@Param("username") String username, @Param("password") String password);

}

