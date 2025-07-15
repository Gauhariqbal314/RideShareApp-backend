package com.example.backend.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.backend.entity.Ride;
import com.example.backend.entity.User;
import com.example.backend.repository.RideRepository;

@Service
public class RideService {
    @Autowired
    private RideRepository rideRepository;

    public Ride bookRide(Ride ride) {
        return rideRepository.save(ride);
    }

    public Ride updateStatus(Long rideId, Ride.Status status, String driverId) {
        Ride ride = rideRepository.findById(rideId).orElseThrow();
        ride.setStatus(status);

        if(status == Ride.Status.ACCEPTED && driverId != null) {
            ride.setDriverId(Long.valueOf(driverId));
        }

        return rideRepository.save(ride);
    }

    public List<Ride> getRideForUser(User user) {
        return rideRepository.findAll().stream()
            .filter(r -> (r.getRiderId() != null && r.getRiderId().equals(user.getId()))
            || (r.getDriverId() != null && r.getDriverId().equals(user.getId()))).toList();
    }
    
    public List<Ride> getRequestedRides() {
        return rideRepository.findAll().stream()
            .filter(r -> r.getStatus() != Ride.Status.COMPLETED)
            .toList();
    }

    public Ride getRideById(Long rideId) {
        return rideRepository.findById(rideId).orElse(null);
    }

}
