package com.zerock.j09.user.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/board")
public class ApiTestController {

    @GetMapping("/list")
    public String[] getList() {

        return new String[] {"AAA", "BBB", "CCC"};

    }

}
