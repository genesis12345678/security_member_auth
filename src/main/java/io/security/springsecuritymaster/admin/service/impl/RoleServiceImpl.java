package io.security.springsecuritymaster.admin.service.impl;

import io.security.springsecuritymaster.admin.repository.RoleRepository;
import io.security.springsecuritymaster.admin.service.RoleService;
import io.security.springsecuritymaster.domain.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Transactional(readOnly = true)
    public Role getRole(long id) {
        return roleRepository.findById(id).orElse(new Role());
    }

    @Transactional(readOnly = true)
    public List<Role> getRoles() {
        return roleRepository.findAll();
    }

    @Transactional(readOnly = true)
    public List<Role> getRolesWithoutExpression() {
        return roleRepository.findAllRolesWithoutExpression();
    }

    public void createRole(Role role){
        roleRepository.save(role);
    }

    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }
}