#pragma once

void FfbPublishForce(unsigned int torque, unsigned int spring, unsigned int friction);
void FfbPublishPhysics(float slip, float spring, float friction, float collisions,
	unsigned int rumbleFrames);
