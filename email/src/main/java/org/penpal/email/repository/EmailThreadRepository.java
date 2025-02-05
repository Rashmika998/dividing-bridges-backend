package org.penpal.email.repository;

import org.penpal.email.model.EmailThread;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface EmailThreadRepository extends MongoRepository<EmailThread, String> {
    List<EmailThread> findByParticipantsContaining(String participant);
    Optional<EmailThread> findByThreadId(String threadId);
    List<EmailThread> findByMessagesSentAtBetween(LocalDateTime start, LocalDateTime end);
    @Query("{ 'participantsStatus.email': ?0, 'participantsStatus.isRead': ?1 }")
    List<EmailThread> findUnreadThreadsByUserEmail(String email, boolean read);
}
