package io.security.springsecuritymaster.admin.service.impl;

import io.security.springsecuritymaster.admin.repository.ResourcesRepository;
import io.security.springsecuritymaster.admin.service.ResourcesService;
import io.security.springsecuritymaster.domain.entity.Resources;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class ResourcesServiceImpl implements ResourcesService {

    private final ResourcesRepository resourcesRepository;

    @Transactional(readOnly = true)
    public Resources getResources(long id) {
        return resourcesRepository.findById(id).orElse(new Resources());
    }

    @Transactional(readOnly = true)
    public List<Resources> getResources() {
        return resourcesRepository.findAll(Sort.by(Sort.Order.asc("orderNum")));
    }

    public void createResources(Resources resources){
        resourcesRepository.save(resources);
    }

    public void deleteResources(long id) {
        resourcesRepository.deleteById(id);
    }
}
