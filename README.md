# idshwk4

## Detection Requirements

Detect http scan based on 404 response

In every 10 minutes
- If the count of 404 response > 2
- and if the 404 ratio > 20%
- and if (the unique count of url response 404 / the count of 404 response) > 0.5 

then out put " x.x.x.x is a scanner with y scan attemps on z urls" 
where
- x.x.x.x is the orig_h
- y is the count of 404 response
- z is the unique count of url response 404
